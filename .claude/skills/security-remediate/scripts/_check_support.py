"""Paths, ids and subprocess helpers shared by the `check` phases."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess


def ids(spec: str) -> list[str]:
    return [x.strip() for x in (spec or "").split(",") if x.strip()]


def src_root(path: str) -> str | None:
    parts = path.split("/")
    return "/".join(parts[:parts.index("src") + 1]) if "src" in parts else None


def owning_tree(path: str) -> str:
    """`//<component root>/...` — the parent of `src`, else the file's directory."""
    parts = path.split("/")
    root = "/".join(parts[:parts.index("src")]) if "src" in parts else os.path.dirname(path)
    return "//%s/..." % root


def trees_for(a) -> list[str]:
    """Owning tree always; the dependents' trees too at `wide` (CLAUDE.md rule 15:
    a changed dependency-facing declaration is judged by what binds to it)."""
    files = [a.file] + (ids(a.related) if a.tier != "local" else [])
    out: list[str] = []
    for f in files:
        t = owning_tree(f)
        if t not in out:
            out.append(t)
    return out


def slug(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def run_json(cmd: list[str], env: dict | None = None) -> tuple[int, dict, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    doc: dict = {}
    # The whole stdout, else its trailing JSON object if the tool printed prose
    # first. An unparseable result stays `{}`, which every caller reads as infra.
    for cand in (p.stdout, (re.search(r"(\{.*\})\s*$", p.stdout, re.S) or [None, ""])[1]):
        try:
            doc = json.loads(cand)
            break
        except (ValueError, TypeError):
            continue
    return p.returncode, doc, (p.stderr or "")[-600:]


def dirty(paths: list[str]) -> list[str]:
    p = subprocess.run(["git", "status", "--porcelain", "--", *paths], capture_output=True, text=True)
    return [ln[3:] for ln in p.stdout.splitlines() if ln.strip()]
