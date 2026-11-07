# SPDX-License-Identifier: Apache-2.0
"""Entry point: judge the tree against the register, in both directions of the ratchet."""

from __future__ import annotations

import sys

from _module_size.config import REGISTRY_REL, REPO, THRESHOLD
from _module_size.emit import emit_registry
from _module_size.growth import Ledger, check_baseline_growth
from _module_size.measure import (
    check,
    check_transitions,
    empty_scope_is_failure,
    register,
)

import _ratchet  # noqa: E402


def _baseline_problems(
    reg: _ratchet.Register, registry: dict[str, dict], measured: dict[str, int]
) -> tuple[list[str], str]:
    """Transition and growth problems against `origin/main`, and where they were judged."""
    baseline = reg.at(_ratchet.BASE)
    if isinstance(baseline, _ratchet.Unreadable):
        problem = _ratchet.unreadable_problem(REGISTRY_REL, _ratchet.BASE, baseline)
        return [problem], "nowhere"
    previous = baseline.entries if isinstance(baseline, _ratchet.Present) else {}
    problems = check_transitions(previous, registry) + check_baseline_growth(
        registry, Ledger(previous, measured, REPO)
    )
    return problems, f"against {_ratchet.BASE}"


def _report_failure(problems: list[str]) -> int:
    print(f"module-size gate: FAIL — {len(problems)} problem(s)")
    for p in problems:
        print(f"  - {p}")
    print(
        f"\nMeasurement: production lines = every line not inside a test region (a region opens at ^#[cfg((all()?test and closes with its module; counting resumes after it); threshold {THRESHOLD} (ADR-MCPRE-061 §5.1)."
    )
    return 1


def _report_ok(registry: dict[str, dict], examined: int, baseline_note: str) -> int:
    def with_status(name: str) -> int:
        return sum(1 for e in registry.values() if e.get("status") == name)

    unreviewed = with_status("unreviewed")
    excepted = with_status("reviewed-exception")
    action_required = with_status("reviewed-action-required")
    print(
        f"module-size gate: OK — {examined} production Rust files examined against a "
        f"{THRESHOLD}-line threshold (production lines = every line not inside a test region (a region opens at ^#[cfg((all()?test and closes with its module; counting resumes after it); ADR-MCPRE-061 §5.1). Debt registry: "
        f"{len(registry)} file(s) — {unreviewed} unreviewed, {excepted} reviewed-exception, "
        f"{action_required} reviewed-action-required. No new oversized file, no registered "
        f"file grew. Disposition transitions and upward baseline authorizations checked "
        f"{baseline_note}."
    )
    return 0


def main() -> int:
    if "--emit-registry" in sys.argv:
        return emit_registry()

    reg = register()
    try:
        registry = reg.current()
    except _ratchet.RegisterError as exc:
        print(f"module-size gate: FAIL — {exc}")
        return 1
    schema_problems = reg.problems(registry)
    measured: dict[str, int] = {}
    problems, examined = check(REPO, registry, measured)
    baseline_problems, baseline_note = _baseline_problems(reg, registry, measured)
    problems = schema_problems + problems + baseline_problems

    if empty_scope_is_failure(examined):
        print("module-size gate: FAIL — examined 0 production Rust files. A gate that "
              "measured nothing is not a pass.")
        return 1

    if problems:
        return _report_failure(problems)
    return _report_ok(registry, examined, baseline_note)
