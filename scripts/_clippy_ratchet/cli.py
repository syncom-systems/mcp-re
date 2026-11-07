# SPDX-License-Identifier: Apache-2.0
"""Run the gate: allow discipline, the register's shape, then the measurement against the baseline."""

from __future__ import annotations

from collections import Counter

import _ratchet

from _clippy_ratchet.allow import allow_discipline
from _clippy_ratchet.config import ADOPTED, RATCHETED, REGISTRY_REL, REPO, SCHEMA
from _clippy_ratchet.measure import measure
from _clippy_ratchet.registry import compare, load_registry


def _fail(header: str, problems: list[str]) -> int:
    print(f"clippy-ratchet gate: FAIL — {header}")
    for problem in problems:
        print(f"  - {problem}")
    return 1


def _ok_line(counts: Counter, baseline: dict[str, int], scanned: int) -> str:
    total = sum(n for k, n in counts.items() if k.split("::", 1)[1] in RATCHETED)
    at_zero = [lint for lint in ADOPTED if lint not in RATCHETED]
    return (
        f"clippy-ratchet gate: OK — production library and binary flavors only. "
        f"Denied at zero: {', '.join('clippy::' + lint for lint in at_zero)}; "
        f"{total} baselined occurrence(s) of "
        f"{', '.join(RATCHETED)} across {len(baseline)} crate/lint entries, none grew. "
        f"Allow discipline: {scanned} file(s) scanned, no crate/module-wide or "
        f"unjustified exception."
    )


def emit_registry() -> int:
    counts, _ = measure(REPO)
    print("# Emitted by scripts/clippy_ratchet_gate.py --emit-registry")
    for key, n in sorted(counts.items()):
        crate, lint = key.split("::", 1)
        if lint not in RATCHETED:
            continue
        print("\n[[debt]]")
        print(f'crate = "{crate}"')
        print(f'lint = "{lint}"')
        print(f"count = {n}")
    return 0


def judge() -> int:
    discipline, scanned = allow_discipline(REPO)
    if scanned == 0:
        print("clippy-ratchet gate: FAIL — scanned 0 production Rust files for allow "
              "discipline. A scan that examined nothing is not a pass.")
        return 1
    if discipline:
        return _fail(f"{len(discipline)} allow-discipline problem(s)", discipline)

    baseline, schema_problems = load_registry(_ratchet.Register(REGISTRY_REL, SCHEMA, REPO))
    if schema_problems:
        return _fail(f"{len(schema_problems)} register problem(s)", schema_problems)
    counts, messages = measure(REPO)
    if messages == 0:
        print("clippy-ratchet gate: FAIL — clippy produced no messages at all. A lane that "
              "compiled nothing is not a pass.")
        return 1

    problems = compare(counts, baseline)
    if problems:
        return _fail(f"{len(problems)} problem(s)", problems)
    print(_ok_line(counts, baseline, scanned))
    return 0
