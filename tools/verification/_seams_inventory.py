# SPDX-License-Identifier: Apache-2.0
"""The seam INVENTORY: every escape-hatch hit in scope (`scan`), the sites the tree declares
(`live_sites`), and the registered sites that name nothing (`stale_sites`)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from _seams_items import declared_items, site_key
from _seams_patterns import MECHANISMS, PRODUCTION_MECHANISMS, code_of, production_lines

SCANNED_SUFFIXES = {".rs", ".lean", ".v"}

#: Generated Lean is machine-owned and may legitimately contain extraction artifacts. It is
#: excluded from the token scan and covered instead by the generated-drift gate: a
#: hand-edit there is caught by regeneration mismatch, which is the stronger control.
#:
#: Reproducers are standalone crates outside the Cargo workspace, in no unit's paths and in
#: no lane's input. Nothing there can make any unit's proof pass, so a token there is not an
#: escape hatch — it is a bug report about the prover.
EXCLUDED = ("verification/lean/generated/", "verification/reproducers/")

#: One escape-hatch hit: `(path relative to the root, line, mechanism, line text, owning
#: units, site key)`.
Hit = tuple[Path, int, str, str, frozenset[str], str | None]

def _unit_paths(unit: dict, repo_root: Path):
    return (
        path for declared in unit["paths"] for path in repo_root.glob(declared) if path.is_file()
    )


def unit_files(verification: dict, repo_root: Path) -> dict[Path, set[str]]:
    """Every existing file a `verification.toml` unit names -> the units that name it."""
    files: dict[Path, set[str]] = {}
    for unit in verification.get("unit", []):
        for path in _unit_paths(unit, repo_root):
            files.setdefault(path, set()).add(unit["id"])
    return files


def _verification_tree_scope(
    declared: dict[Path, set[str]], repo_root: Path
) -> dict[Path, tuple[bool, frozenset[str]]]:
    """The files under `verification/`, none of them production, each with its owning units."""
    verification_dir = repo_root / "verification"
    if not verification_dir.exists():
        return {}
    return {
        path: (False, frozenset(declared.get(path, ())))
        for path in verification_dir.rglob("*")
        if path.is_file() and path.suffix in SCANNED_SUFFIXES
    }


def _with_production_scope(
    scoped: dict[Path, tuple[bool, frozenset[str]]], declared: dict[Path, set[str]]
) -> None:
    """Add every declared file the tree scope did not already hold, as production."""
    for path, owners in declared.items():
        if path.suffix in SCANNED_SUFFIXES:
            scoped.setdefault(path, (True, frozenset(owners)))


def _is_excluded(path: Path, repo_root: Path) -> bool:
    rel = path.relative_to(repo_root).as_posix()
    return any(rel.startswith(prefix) for prefix in EXCLUDED)


def scan_paths(verification: dict, repo_root: Path) -> list[tuple[Path, bool, frozenset[str]]]:
    """(file, is_production, owning units) for everything in scope, in a stable order."""
    declared = unit_files(verification, repo_root)
    scoped = _verification_tree_scope(declared, repo_root)
    _with_production_scope(scoped, declared)
    return [
        (path, *scoped[path]) for path in sorted(scoped) if not _is_excluded(path, repo_root)
    ]


@dataclass(frozen=True)
class _Source:
    """One scanned file: what a hit in it needs to name its site."""

    path: Path
    rel: str
    lines: list[str]
    items: list[tuple[int, str]]
    owners: frozenset[str]

    def hit(self, lineno: int, name: str, line: str) -> Hit:
        key = site_key(self.rel, self.lines, lineno, self.items)
        return (self.path, lineno, name, line.strip(), self.owners, key)


def _matching_names(mechanisms: dict[str, str], line: str) -> list[str]:
    """The mechanisms `line` carries. Comments are not code: one rule, `code_of`, for this
    census and for the boundary rule that asks which seams a proof trusts."""
    code = code_of(line)
    return [name for name, pattern in mechanisms.items() if re.search(pattern, code)]


def _file_hits(
    path: Path, is_production: bool, owners: frozenset[str], repo_root: Path
) -> list[Hit]:
    mechanisms = PRODUCTION_MECHANISMS if is_production else MECHANISMS
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    # One declaration pass per file, shared by every seam in it: the qualifier of an item
    # is decided by the blocks open above it, and re-deriving that per seam is quadratic
    # in exactly the specification files that carry the most seams.
    source = _Source(path.relative_to(repo_root), rel, lines, declared_items(lines), owners)
    numbered = production_lines(text) if is_production else list(enumerate(lines, start=1))
    return [
        source.hit(lineno, name, line)
        for lineno, line in numbered
        for name in _matching_names(mechanisms, line)
    ]


def scan(verification: dict, repo_root: Path) -> list[Hit]:
    """Every escape-hatch hit in scope: production Rust in its code forms, the rest in full."""
    hits: list[Hit] = []
    for path, is_production, owners in scan_paths(verification, repo_root):
        hits += _file_hits(path, is_production, owners, repo_root)
    return hits


def _none_mechanism_sites(assumptions: dict) -> list[str]:
    return [
        str(site)
        for entry in assumptions.get("assumption", [])
        if entry["tool_specific_mechanism"].startswith("none:")
        for site in entry.get("sites", [])
    ]


def _declared_names(repo_root: Path, path: str) -> set[str]:
    try:
        text = (repo_root / path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        text = ""
    return {name for _, name in declared_items(text.splitlines())}


def declared_seam_sites(assumptions: dict, repo_root: Path) -> set[str]:
    """The registered sites of `none:` assumptions whose item is declared in the tree.

    A `none:` mechanism (`trusted-seam`, `trusted-primitive`) is a premise no scanner
    pattern can see, so its site is never among the escape-hatch hits and cannot be
    confirmed live by one. It is confirmed the only way it can be: the file exists and
    declares the item the key names. A renamed or moved item stops resolving and is
    reported as stale, exactly as a Verus site is. The key is the one `site_key` derives,
    so an enum variant (not an item) is named by its enum.

    WHAT THIS ESTABLISHES, AND NOTHING MORE: that a file at the registered path declares an
    item of the registered name. It does not establish that the premise holds (a
    `trusted-seam` is by definition not checked by any code), nor that the item still does
    what the premise's justification says, nor that a renamed successor is the same seam. A
    passing site is a location, never a proof; the premise stays `assumed` or
    `external-boundary` in the registry.
    """
    declared: dict[str, set[str]] = {}
    resolved: set[str] = set()
    for site in _none_mechanism_sites(assumptions):
        path, _, item = site.partition("#")
        if path not in declared:
            declared[path] = _declared_names(repo_root, path)
        if item in declared[path]:
            resolved.add(site)
    return resolved


def live_sites(
    verification: dict, assumptions: dict, repo_root: Path, hits: list[Hit] | None = None
) -> set[str]:
    """Every seam site the tree declares: each escape-hatch hit's item, and each declared
    item a `none:` premise registers. `hits` is a `scan` the caller already ran."""
    found = scan(verification, repo_root) if hits is None else hits
    return {hit[5] for hit in found if hit[5]} | declared_seam_sites(assumptions, repo_root)


def stale_sites(assumptions: list[dict], live: set[str] | frozenset[str]) -> dict[str, list[str]]:
    """Assumption id -> the registered sites that name no seam in `live`.

    A site key is derived from the ITEM a seam sits on, so it survives formatting but not a
    rename or a deletion. An entry left pointing at a seam that no longer exists reads as
    trust the tree no longer needs.
    """
    out: dict[str, list[str]] = {}
    for entry in assumptions:
        gone = sorted({str(site) for site in entry.get("sites", [])} - set(live))
        if gone:
            out[entry["id"]] = gone
    return out
