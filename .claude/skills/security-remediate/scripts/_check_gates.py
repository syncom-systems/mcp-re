"""The gate parts `check post` runs: prescan, pyright, one bazel tree, and their summary."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from _check_support import run_json, slug, src_root

PYRIGHT_SUMMARY = re.compile(r"(\d+) errors?, (\d+) warnings?")
_RUST_PARTS = ("clippy", "rustfmt", "test", "module-size", "registry", "targets")


def _prescan_root(a, root: str, watch: set) -> tuple[int, list[dict]]:
    out = os.path.join(a.work_dir, "prescan-%s.json" % slug(root))
    p = subprocess.run([sys.executable, a.prescan_script, root, "--json", out],
                       capture_output=True, text=True)
    try:
        doc = json.load(open(out, encoding="utf-8"))
    except (OSError, ValueError):
        return p.returncode, [{"root": root, "error": "prescan wrote no JSON (exit %d)" % p.returncode}]
    hits = []
    for f in doc.get("findings", []):
        rel = os.path.join(root, f["file"]) if f.get("file") else None
        if rel in watch:
            hits.append({"file": rel, "line": f.get("line"), "kind": f.get("kind"),
                         "severity": f.get("severity"), "symbol": f.get("symbol")})
    return p.returncode, hits


def prescan(a, touched: list[str], related: list[str]) -> dict:
    watch = set(touched) | set(related) | {a.file}
    roots = sorted({r for r in (src_root(f) for f in touched) if r})
    hits, exits = [], {}
    for root in roots:
        exits[root], found = _prescan_root(a, root, watch)
        hits += found
    return {"roots": roots, "exits": exits, "hits": hits,
            "state": "clean" if not hits else "hits"}


def _last_summary(text: str):
    last = None
    for last in PYRIGHT_SUMMARY.finditer(text):
        pass
    return last


def pyright(a) -> dict:
    log = os.path.join(a.work_dir, "pyright-%s.log" % slug(a.file))
    env = dict(os.environ, NODE_OPTIONS="--max-old-space-size=12288")
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(a.pyright_cmd.split(), stdout=fh, stderr=subprocess.STDOUT, env=env)
    text = open(log, encoding="utf-8", errors="replace").read()
    m = _last_summary(text)
    if m is None:
        # No summary line at all: exit 250 is the node heap OOM, which reads like
        # "clean" if only the exit code or the tail is inspected.
        return {"verdict": "infra", "exit": p.returncode, "log": log,
                "why": "no pyright summary line (heap OOM or crash) — NOT a clean run"}
    errors, warnings = int(m.group(1)), int(m.group(2))
    verdict = "new-failures" if errors > a.pyright_baseline_errors else "ok"
    detail = [ln.strip() for ln in text.splitlines() if " - error:" in ln][:20] \
        if verdict != "ok" else []
    return {"verdict": verdict, "exit": p.returncode, "errors": errors, "warnings": warnings,
            "baseline_errors": a.pyright_baseline_errors, "log": log, "errors_head": detail}


def bazel(a, tree: str) -> dict:
    rc, doc, err = run_json([sys.executable, a.gate_script, "check", "--tree", tree,
                             "--store", a.store])
    v = doc.get("verdict") or "infra"
    return {"tree": tree, "verdict": v, "exit": rc,
            "new_failures": doc.get("new_failures", []),
            "executed": doc.get("executed"), "total": doc.get("total"),
            "infra_errors": doc.get("infra_errors", [])[:3],
            "note": ("no test targets ran — this tree's bazel half measured nothing"
                     if v == "infra" and not doc.get("total") else ""),
            **({"stderr_tail": err} if v == "infra" and err else {})}


def _first(p: dict, *keys: str):
    """The first of `keys` the part carries a value for, else the empty string."""
    return next((p[k] for k in keys if p.get(k)), "")


def _rust_summary(p: dict) -> str:
    what = _first(p, "lane", "target")
    bad = _first(p, "errors_head", "unformatted", "failed", "debt", "head", "why")
    return "%s%s %s%s" % (p["gate"], (":" + what) if what else "", p["verdict"],
                          (" — " + str(bad)[:200]) if bad and p["verdict"] != "ok" else "")


def gate_summary(p: dict) -> str:
    """One line per gate part for the journal. Every Rust part is named here; only the
    Python tree part carries `new_failures`."""
    if p["gate"] in _RUST_PARTS:
        return _rust_summary(p)
    if p["gate"] == "pyright":
        return "pyright %s (%s errors vs %s)" % (p["verdict"], p.get("errors", "?"),
                                                  p.get("baseline_errors"))
    tail = (" new: " + ",".join(p["new_failures"][:5])) if p.get("new_failures") else ""
    return "bazel %s %s%s%s" % (p.get("tree", "?"), p["verdict"], tail,
                                (" — " + p["note"]) if p.get("note") else "")
