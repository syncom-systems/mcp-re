"""The register: schema rules, the ratchet, the disposition lifecycle and UC-3."""

from __future__ import annotations

import subprocess
from pathlib import Path

import _ratchet
from _unit_closure.config import PERMITTED_TRANSITIONS, REPO, STATUSES, exclusions


def permitted_transition(old: str, new: str) -> bool:
    """Whether a disposition may move from `old` to `new`. Total, so the selftest can
    assert the relation rather than re-implement it."""
    return (old, new) in PERMITTED_TRANSITIONS


def validate_register(register: dict[str, dict], root: Path = REPO) -> list[str]:
    """The register's schema, and the rule only this register has: `reviewed-out-of-cone`
    carries the `reason` no unit's claim reaches the file."""
    problems = exclusions(root).problems(register)
    for rel, entry in sorted(register.items()):
        if entry.get("status") == "reviewed-out-of-cone" and not entry.get("reason"):
            problems.append(
                f"{rel}: `reviewed-out-of-cone` without a `reason` — the whole content of "
                f"that disposition is why no unit's claim reaches this file"
            )
    return problems


def _unanswered_or_mismatched(rel: str, why: str, entry: dict | None) -> str | None:
    """The problem with one flagged path, or None when its entry answers it."""
    if entry is None:
        return (
            f"{rel}: {why}. Add it to a unit's `paths`, or record it in "
            f"config/unit-closure-exclusions.toml with a disposition"
        )
    if entry.get("rule") and entry["rule"] != why.split(":", 1)[0]:
        return (
            f"{rel}: registered under `{entry['rule']}` but now {why} — the register "
            f"records a different escape from the one the tree has"
        )
    return None


def check_register(findings: dict[str, str], register: dict[str, dict]) -> list[str]:
    """The ratchet: every flagged path answered, every answer still needed, each for its
    stated reason."""
    answers = (
        _unanswered_or_mismatched(rel, why, register.get(rel))
        for rel, why in sorted(findings.items())
    )
    problems = [problem for problem in answers if problem is not None]
    problems += [
        f"{rel}: registered as outside every unit's closure, but nothing flags it "
        f"any more — a resolved entry must be removed, not left standing"
        for rel in sorted(register)
        if rel not in findings
    ]
    return problems


def check_transitions(previous: dict[str, dict], current: dict[str, dict]) -> list[str]:
    moves = (
        (rel, before.get("status"), entry.get("status"))
        for rel, before, entry in _ratchet.transitions(previous, current)
    )
    return [
        f"{rel}: disposition moved `{old}` -> `{new}`, which the lifecycle does not "
        f"permit — a completed census may not be returned to `unreviewed`, because "
        f"that tells the next reader nobody has looked"
        for rel, old, new in moves
        if old in STATUSES and new in STATUSES and not permitted_transition(old, new)
    ]


def check_new_debt(register: dict[str, dict], new_paths: set[str]) -> list[str]:
    """UC-3. A path this change introduced may not be answered with a register entry."""
    return [
        f"{rel}: new since origin/main and registered as an exclusion — UC-3 admits no new "
        f"debt. A file added or moved by this change must join a unit's `paths`"
        for rel in sorted(register)
        if rel in new_paths
    ]


def _is_introduced(parts: list[str], previous: dict[str, dict]) -> str | None:
    """The path one `git diff --name-status` row adds, or None when it adds none."""
    if parts[0].startswith("A") and len(parts) == 2:
        return parts[1]
    renamed_new = parts[0].startswith("R") and len(parts) == 3 and parts[1] not in previous
    return parts[2] if renamed_new else None


def introduced_paths(previous: dict[str, dict], ref: str = _ratchet.BASE) -> set[str] | None:
    """Rust files this branch ADDS relative to `ref`; None when git cannot answer.

    A rename carries its answer with it only when the old path had one in `previous`, the
    register at `ref`; otherwise the new name is as new as an addition, and UC-3 treats it
    that way. None is a refusal, not an empty set: an empty set would admit every entry.
    """
    proc = subprocess.run(
        ["git", "diff", "--name-status", "-M", f"{ref}...HEAD"],
        cwd=REPO, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    rows = (line.split("\t") for line in proc.stdout.splitlines())
    added = (_is_introduced(parts, previous) for parts in rows)
    return {path for path in added if path is not None}


def empty_scope_is_failure(units: int, walked: int) -> bool:
    """A gate whose subject list can become empty reports success by measuring nothing.

    Deleting the `[[unit]]` table does not raise in the manifest loader — probed, it returns
    a document with zero units — so the refusal has to live here. Named so the selftest can
    assert the contract rather than re-implement it.
    """
    return units == 0 or walked == 0
