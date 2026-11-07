"""The usage map: who imports, constructs, subclasses or references a symbol."""
from __future__ import annotations

import os
import subprocess

from _prepare_pysites import py_sites
from _prepare_rust import rs_binds
from _prepare_textsites import text_sites

_RANK = {"subclass": 0, "construct": 1, "ref": 2, "import": 3}


def is_test(path: str) -> bool:
    base = os.path.basename(path)
    return "/tests/" in path or base.startswith("test_") or base.endswith("_test.py") \
        or "/tests.rs" in path or base == "conftest.py"


def top_package(path: str) -> str | None:
    """The importable top-level package: the path segment right after `src`."""
    parts = path.split("/")
    if "src" in parts and parts.index("src") + 1 < len(parts) - 1:
        return parts[parts.index("src") + 1]
    return None


def _sites_in(sym: str, own: str, cand: str, pkg: str | None) -> tuple[list[tuple[str, int]], list[str]]:
    """The uses of `sym` in one candidate file, and that file's lines."""
    try:
        src = open(cand, encoding="utf-8", errors="replace").read()
    except OSError:
        return [], []
    lines = src.splitlines()
    if cand.endswith(".py") and pkg:
        return py_sites(sym, cand, pkg, src), lines
    if cand.endswith(".rs"):
        if not rs_binds(cand, own, src):
            return [], lines
        return text_sites(sym, lines, True), lines
    return text_sites(sym, lines, False), lines


def _git_grep(sym: str, lang_globs: list[str]) -> tuple[list[str], str | None]:
    """Tracked files naming `sym` as a word, or the reason the search failed."""
    p = subprocess.run(["git", "grep", "-l", "-I", "-w", "-e", sym, "--", *lang_globs],
                       capture_output=True, text=True)
    if p.returncode not in (0, 1):
        return [], (p.stderr or "git grep failed").strip()[:200]
    return p.stdout.splitlines(), None


def _production_sites(cand: str, found: list[tuple[str, int]], lines: list[str]) -> list[tuple[int, str]]:
    def text(ln: int) -> str:
        return lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
    return [(_RANK[k], "%s:%d [%s] %s" % (cand, ln, k, text(ln)[:140])) for k, ln in found]


def usages(sym: str, own: str, lang_globs: list[str], max_sites: int) -> dict:
    """Production and test uses of `sym`, with the first sites ranked by weight.

    Candidates come from `git grep -l -w` over tracked files — it cannot wander
    into `.venv`, `dist/` or a build cache, which is what made the evaluators'
    own greps need `| grep -v .venv` tails. For Python each candidate is then
    confirmed by `py_sites`; Rust has no binding check and is text-classified,
    so a Rust count is an UPPER bound and says so.
    """
    files, error = _git_grep(sym, lang_globs)
    if error:
        return {"error": error}
    pkg = top_package(own)
    prod: dict[str, int] = {"import": 0, "construct": 0, "subclass": 0, "ref": 0}
    tests = 0
    sites: list[tuple[int, str]] = []
    for cand in [f for f in files if f != own]:
        found, lines = _sites_in(sym, own, cand, pkg)
        if is_test(cand):
            tests += len(found)
            continue
        for kind, _ln in found:
            prod[kind] += 1
        sites += _production_sites(cand, found, lines)
    sites.sort(key=lambda s: s[0])
    total = len(sites)
    return {"prod": prod, "tests": tests, "bound": bool(pkg and own.endswith(".py")),
            "sites": [s for _, s in sites[:max_sites]],
            "truncated": total > max_sites, "total_prod_sites": total}
