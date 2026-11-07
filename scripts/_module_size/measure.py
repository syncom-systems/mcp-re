# SPDX-License-Identifier: Apache-2.0
"""The per-file ratchet: measure production lines and judge them against the register."""

from __future__ import annotations

from pathlib import Path

from _module_size.config import (
    PERMITTED_TRANSITIONS,
    REGISTRY_REL,
    REPO,
    SCHEMA,
    STATUSES,
    THRESHOLD,
)

import _ratchet  # noqa: E402
from _rust_source import crate_sources, production_view  # noqa: E402


def register(root: Path = REPO) -> _ratchet.Register:
    return _ratchet.Register(REGISTRY_REL, SCHEMA, root)


def production_lines(text: str) -> int:
    """Every line of a Rust source that is NOT inside a test region.

    The region rule is `tools/verification/_rust_source.py`'s: a region runs from its
    `#[cfg(test)]`-family attribute to the end of the item it introduces, tracked by brace
    depth over code characters only, and counting resumes afterwards. This gate asks the
    owner for the view and counts it; the prose in ADR-MCPRE-061 §5.1 describes the rule.
    """
    return len(production_view(text))


def _file_problem(rel: str, prod: int, entry: dict | None) -> str | None:
    """The ratchet's verdict on one measured file, or None when it stands."""
    if prod <= THRESHOLD:
        if entry is None:
            return None
        return (
            f"{rel}: now {prod} production lines (<= {THRESHOLD}) but still in the "
            f"debt registry — remove the entry, the debt is paid"
        )
    if entry is None:
        return (
            f"{rel}: {prod} production lines exceeds {THRESHOLD} and is not in the debt "
            f"registry — decompose it, or record an ADR-MCPRE-061 §14 exception"
        )
    baseline = int(entry["baseline_prod_loc"])
    if prod > baseline:
        return (
            f"{rel}: grew from {baseline} to {prod} production lines — the ratchet only "
            f"turns one way"
        )
    return None


def _measure_sources(
    root: Path, registry: dict[str, dict], measured: dict[str, int]
) -> tuple[list[str], int]:
    """Measure every production source into `measured` and collect the ratchet's verdicts."""
    problems: list[str] = []
    sources = crate_sources(root)
    for p in sources:
        rel = str(p.relative_to(root))
        measured[rel] = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        problem = _file_problem(rel, measured[rel], registry.get(rel))
        if problem is not None:
            problems.append(problem)
    return problems, len(sources)


def _stale_entries(registry: dict[str, dict], measured: dict[str, int]) -> list[str]:
    return [
        f"{rel}: in the debt registry but not found — a stale entry hides a moved "
        f"or deleted file"
        for rel in registry
        if rel not in measured
    ]


def check(
    root: Path, registry: dict[str, dict], out_measured: dict[str, int] | None = None
) -> tuple[list[str], int]:
    """Return (problems, files_examined), filling `out_measured` with path -> production LOC.

    `check_baseline_growth` needs the same measurement to decide whether a raised baseline
    matches the file it describes. It is handed out rather than measured again: two passes
    over the tree are two chances for the two numbers to differ.
    """
    measured: dict[str, int] = out_measured if out_measured is not None else {}
    problems, examined = _measure_sources(root, registry, measured)
    return problems + _stale_entries(registry, measured), examined


def permitted_transition(old: str, new: str) -> bool:
    """Whether a disposition may move from `old` to `new` (ADR-MCPRE-061 §14).

    Total, so the selftest can assert the relation rather than re-implement it. An
    unknown status is not a transition question — the register's schema rejects it first.
    """
    return (old, new) in PERMITTED_TRANSITIONS


def empty_scope_is_failure(examined: int) -> bool:
    """A gate that examined nothing must not report OK. Named so the selftest can assert
    the contract rather than re-implement it."""
    return examined == 0


def check_transitions(previous: dict[str, dict], current: dict[str, dict]) -> list[str]:
    """Refuse a disposition change ADR-MCPRE-061 §14 does not permit.

    Only entries present in BOTH registries are transitions. An entry that appears is a
    new debt (the threshold rules judge it) and one that disappears is a paid or removed
    debt (the `debt is paid` and `not in the debt registry` rules judge that).
    """
    problems = []
    for rel, before, entry in _ratchet.transitions(previous, current):
        old = before.get("status")
        new = entry.get("status")
        if old not in STATUSES or new not in STATUSES:
            continue
        if not permitted_transition(old, new):
            problems.append(
                f"{rel}: disposition moved `{old}` -> `{new}`, which ADR-MCPRE-061 §14 does "
                f"not permit — a completed census may not be returned to `unreviewed`, "
                f"because that tells the next reader nobody has looked"
            )
    return problems
