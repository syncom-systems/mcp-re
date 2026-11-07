"""Driver of the structural pre-scan: argument handling, the two passes, the JSON
result and the stderr summary."""

import json
import os
import sys

from _prescan_allow import Allowlist, load_allow
from _prescan_collect import collect_sources
from _prescan_python import python_pass
from _prescan_rust import rust_pass
from _prescan_sink import Sink

_USAGE = "usage: prescan.py <dir> [--json out.json] [--allow allow.json]"


def _scan(root, sources, allow):
    findings = []

    def add(kind, severity, symbol, file, line, detail):
        findings.append({
            "kind": kind, "severity": severity, "symbol": symbol,
            "file": os.path.relpath(file, root) if file else None,
            "line": line, "detail": detail})

    if sources.py_files:
        python_pass(sources.py_files, root, add, allow)
    if sources.rs_files:
        rust_pass(sources.rs_files, sources.crates, Sink(root, add, Allowlist(allow)))
    return findings


def _result(root, sources, findings):
    blocks = [f for f in findings if f["severity"] == "block"]
    languages = (["python"] if sources.py_files else []) + \
        (["rust"] if sources.rs_files else [])
    return {
        "service_src": root,
        "languages": languages,
        "verdict": "NO-GO" if blocks else "GO",
        "counts": {
            "block": len(blocks),
            "warn": len([f for f in findings if f["severity"] == "warn"]),
            "py_files": len(sources.py_files), "rs_files": len(sources.rs_files),
            "crates": len(sources.crates),
        },
        "roles": sources.roles_seen,
        "crates": {info["name"]: {"is_bin": info["is_bin"], "is_demo": info["is_demo"],
                                  "has_serve": info["has_serve"],
                                  "has_verify": info["has_verify"]}
                   for info in sources.crates.values()},
        "findings": findings,
    }


def _print_finding(f):
    tag = "BLOCK" if f["severity"] == "block" else "warn "
    loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "-")
    print(f"  [{tag}] {f['kind']:22} {f['symbol']}  ({loc})\n           {f['detail']}",
          file=sys.stderr)


def _print_crate(info):
    kind = "bin" if info["is_bin"] else "demo" if info["is_demo"] else "lib"
    print(f"  crate {info['name']:24} [{kind}] serve=True "
          f"verify={info['has_verify']}", file=sys.stderr)


def _print_summary(root, result):
    counts, verdict = result["counts"], result["verdict"]
    langs = "+".join(result["languages"]) or "none"
    print(f"\n=== STRUCTURAL PRE-SCAN [{langs}]: {os.path.basename(root)} ===",
          file=sys.stderr)
    print(f"verdict: {verdict}   ({counts['block']} blocking, {counts['warn']} "
          f"warnings; {counts['py_files']} py, {counts['rs_files']} rs, "
          f"{counts['crates']} crates)", file=sys.stderr)


def _print_verdict(verdict):
    if verdict == "NO-GO":
        print("\nNO-GO: fix the blocking structural defects before spending the "
              "full-scan token budget.", file=sys.stderr)
    else:
        print("\nGO: structural floor clear — proceed to Stage 2 (pre-run review). "
              "(GO means audit-ready, NOT secure.)", file=sys.stderr)


def _print_report(root, sources, result):
    _print_summary(root, result)
    serving = [i for i in sorted(sources.crates.values(), key=lambda i: i["name"])
               if i["has_serve"]]
    for info in serving:
        _print_crate(info)
    ordered = [f for severity in ("block", "warn") for f in result["findings"]
               if f["severity"] == severity]
    for finding in ordered:
        _print_finding(finding)
    _print_verdict(result["verdict"])


def _root_of(args):
    pos = [a for a in args if not a.startswith("--")]
    if not pos:
        print(_USAGE, file=sys.stderr)
        return None
    root = os.path.abspath(pos[0])
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return None
    return root


def main():
    args = sys.argv[1:]
    root = _root_of(args)
    if root is None:
        return 2
    sources = collect_sources(root)
    result = _result(root, sources, _scan(root, sources, load_allow(args)))
    if "--json" in args:
        with open(args[args.index("--json") + 1], "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    _print_report(root, sources, result)
    print(json.dumps(result))
    return 1 if result["verdict"] == "NO-GO" else 0
