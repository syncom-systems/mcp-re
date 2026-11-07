# SPDX-License-Identifier: Apache-2.0
"""The debt register as counts, and the comparison of a measurement against it."""

from __future__ import annotations

from collections import Counter

import _ratchet

from _clippy_ratchet.config import ADOPTED, REGISTRY


def _entry_counts(entries: dict[str, dict]) -> tuple[dict[str, int], list[str]]:
    counts: dict[str, int] = {}
    problems: list[str] = []
    for key, entry in entries.items():
        if isinstance(entry.get("count"), int):
            counts[key] = entry["count"]
        else:
            problems.append(f"{key}: `count` is {entry.get('count')!r}, not an integer")
    return counts, problems


def load_registry(register: _ratchet.Register) -> tuple[dict[str, int], list[str]]:
    """`{crate::lint: count}`, and every way the register departs from its schema."""
    try:
        entries = register.current()
    except _ratchet.RegisterError as exc:
        return {}, [str(exc)]
    problems = register.problems(entries)
    counts, count_problems = _entry_counts(entries)
    return counts, problems + count_problems


def _growth_problems(counts: Counter, baseline: dict[str, int]) -> list[str]:
    out = []
    for key, n in sorted(counts.items()):
        crate, lint = key.split("::", 1)
        # Every ADOPTED lint is compared. A lint outside RATCHETED has no registry entry,
        # so `baseline.get` yields 0 below and the first occurrence fails — which is what
        # "denied at zero" means here. Skipping non-RATCHETED lints would silently make
        # every zero-debt adoption inert.
        allowed = baseline.get(key, 0)
        if lint in ADOPTED and n > allowed:
            out.append(
                f"{crate}: {n} `clippy::{lint}` in production code, baseline {allowed} — "
                f"the ratchet only turns one way"
            )
    return out


def _shrink_problems(counts: Counter, baseline: dict[str, int]) -> list[str]:
    out = []
    for key, allowed in sorted(baseline.items()):
        if counts.get(key, 0) < allowed:
            crate, lint = key.split("::", 1)
            out.append(
                f"{crate}: `clippy::{lint}` is down to {counts.get(key, 0)} from a baseline "
                f"of {allowed} — lower the baseline in {REGISTRY.name} to lock the gain in"
            )
    return out


def compare(counts: Counter, baseline: dict[str, int]) -> list[str]:
    return _growth_problems(counts, baseline) + _shrink_problems(counts, baseline)
