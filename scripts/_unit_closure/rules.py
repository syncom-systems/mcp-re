"""The two escape rules: UC-1 (a measured file's unmeasured `mod`) and UC-2 (its parent)."""

from __future__ import annotations

from pathlib import Path

from _unit_closure.tree import closure, declares_items, expand, module_children, parent_module


def _uc1_findings(root: Path, rel: str, units_of: list[str], covered) -> list[tuple[str, str]]:
    """`(child, why)` for each `mod` of `rel` that resolves to a file in no unit's paths."""
    return [
        (
            child,
            f"UC-1: `mod {name};` in {rel} ({units_of[0]}) resolves here, and "
            f"this file is in no unit's paths — the unit keeps fingerprinting {rel} "
            f"alone",
        )
        for name, child in module_children(root, rel)
        if child not in covered
    ]


def _is_deciding_outsider(root: Path, parent: str, covered) -> bool:
    """Whether `parent` is in no unit's paths and holds items of its own."""
    return parent not in covered and declares_items(root, parent)


def _uc2_finding(root: Path, rel: str, units_of: list[str], covered) -> tuple[str, str] | None:
    """`(parent, why)` when `rel`'s parent decides things and is in no unit's paths.

    A namespace parent decides nothing; see UC-2.
    """
    parent = parent_module(root, rel)
    if parent is None or not _is_deciding_outsider(root, parent, covered):
        return None
    return parent, (
        f"UC-2: declares {rel} ({units_of[0]}) and holds items of its own, and is "
        f"in no unit's paths — its decisions change with no fingerprint moving"
    )


def _walkable(root: Path, rel: str, walked: set[str]) -> bool:
    return rel not in walked and rel.endswith(".rs") and (root / rel).is_file()


def flag(root: Path, units) -> tuple[dict[str, str], int]:
    """`{path: why}` for every unmeasured neighbour of a measured file, and files walked.

    The walk starts and stays at the closure boundary: it steps out of files that ARE in a
    unit, never out of registered ones. Walking out of a registered file was tried and is
    wrong — `config_state/mod.rs` is itself outside every closure, so demanding that its
    nineteen children be measured is a demand for COVERAGE, not a report of DRIFT, and this
    gate is explicitly not the instrument for coverage (see the module docstring). Moving
    code between two unmeasured files moves no fingerprint and hides nothing.

    The consequence is worth stating, because it looks like the register growing: when a
    registered parent later joins a unit, its children become neighbours of a measured file
    for the first time and are flagged then. That is a newly VISIBLE question, not new debt
    — the question existed and nothing could see it — and answering it is part of the work
    that attached the parent.

    Findings are what the rules flag, NOT what is left unanswered: a registered path is
    still a finding, and `check_register` is the one place an answer silences one. Keeping
    the two apart is what lets the ratchet see an entry whose path nothing flags any more.
    """
    covered = closure(root, units)
    walked: set[str] = set()
    findings: dict[str, str] = {}

    for rel in reversed(sorted(covered)):
        if not _walkable(root, rel, walked):
            continue
        walked.add(rel)
        for child, why in _uc1_findings(root, rel, covered[rel], covered):
            findings.setdefault(child, why)
        parent = _uc2_finding(root, rel, covered[rel], covered)
        if parent is not None:
            findings.setdefault(*parent)

    return findings, len(walked)


def expansion_disagreements(root: Path, units) -> list[str]:
    """Paths where this gate's glob expansion differs from the manifest loader's.

    The gate carries its own `expand` so it can run against a synthetic tree. That is a
    mirror, and an unchecked mirror drifts. Run only against the real repository, where
    `_boundary_crossings.expand_paths` resolves against the same root.
    """
    from _boundary_crossings import expand_paths  # noqa: PLC0415 - real-run only

    problems = []
    for unit in units:
        mine = expand(root, unit["paths"])
        theirs = expand_paths(unit["paths"])
        if mine != theirs:
            problems.append(
                f"{unit['id']}: this gate expands `paths` to {sorted(mine ^ theirs)} "
                f"differently from tools/verification/_boundary_crossings.py — the two must agree "
                f"about what a unit measures"
            )
    return problems
