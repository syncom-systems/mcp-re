# SPDX-License-Identifier: Apache-2.0
"""The gate's own proof: the ratchet in both directions, the §14 lifecycle, the growth rule."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _module_size.config import STATUSES, THRESHOLD
from _module_size.measure import (
    check,
    check_transitions,
    empty_scope_is_failure,
    permitted_transition,
    production_lines,
    register,
)
from _module_size.selftest_growth import selftest_baseline_growth
from _module_size.selftest_support import (
    REL_BIG,
    Probe,
    SelftestFailure,
    ensure,
    entry_for,
)

TURNS_ONE_WAY = "the ratchet only turns one way"


def _empty_scope(root: Path) -> None:
    """An empty scope must FAIL, never print OK."""
    _, examined = check(root, {})
    ensure(examined == 0, "empty tree reported files")
    # main() turns examined == 0 into a failure; check that contract here.
    ensure(empty_scope_is_failure(examined),
           "an empty scope was not treated as a failure")


def _threshold_ratchet(p: Probe) -> None:
    problems, examined = check(p.root, {})
    ensure(any("not in the debt registry" in m for m in problems),
           f"unregistered oversized file passed: {problems}")
    ensure(examined == 2, f"expected 2 files examined, got {examined}")

    baseline = production_lines(p.big.read_text())
    reg = entry_for("unreviewed", baseline)

    problems = p.problems(reg)
    ensure(not problems, f"file at its baseline reported problems: {problems}")

    p.append("fn extra() {}\n")
    problems = p.problems(reg)
    ensure(any(TURNS_ONE_WAY in m for m in problems), f"growth was not caught: {problems}")

    p.set_lines(THRESHOLD + 2)
    problems = p.problems(reg)
    ensure(not problems, f"a shrinking file reported problems: {problems}")

    # Dropping to the threshold requires removing the entry.
    p.big.write_text("fn tiny() {}\n")
    problems = p.problems(reg)
    ensure(any("the debt is paid" in m for m in problems),
           f"paid debt did not require entry removal: {problems}")
    problems = p.problems({})
    ensure(not problems, f"paid debt with entry removed still failed: {problems}")

    # A stale entry naming a file that no longer exists fails.
    stale = {"gone/nowhere.rs": {"path": "gone/nowhere.rs", "baseline_prod_loc": 999,
                                 "baseline_sha": "0" * 7, "status": "unreviewed"}}
    problems = p.problems(stale)
    ensure(any("stale entry" in m for m in problems), f"stale registry entry passed: {problems}")


def _reviewed_dispositions(p: Probe) -> None:
    # `unreviewed` -> `reviewed-exception` is the ADR-MCPRE-061 §14 transition, and it
    # changes what the entry CLAIMS, never what the ratchet ALLOWS.
    (p.root / "record.md").write_text("# EX-000, a §14 record\n")
    p.set_lines(THRESHOLD + 2)
    reviewed = entry_for("reviewed-exception", THRESHOLD + 2,
                         review_ref="EX-000 in record.md")
    ensure(not register(p.root).problems(reviewed),
           "a reviewed exception citing a real record was rejected")
    problems = p.problems(reviewed)
    ensure(not problems, f"a reviewed exception at its baseline failed: {problems}")

    # An exception is not a licence to grow.
    p.append("fn extra() {}\n")
    problems = p.problems(reviewed)
    ensure(any(TURNS_ONE_WAY in m for m in problems),
           f"a reviewed exception was allowed to grow: {problems}")

    # A completed census whose disposition is "decompose first" is still a completed
    # census, and the registry has a state for it.
    p.set_lines(THRESHOLD + 2)
    action = {REL_BIG: dict(reviewed[REL_BIG], status="reviewed-action-required")}
    ensure(not register(p.root).problems(action),
           "a reviewed-action-required entry with a record was rejected")
    problems = p.problems(action)
    ensure(not problems, f"reviewed-action-required at its baseline failed: {problems}")

    # ...and it is not a licence to grow either.
    p.append("fn more() {}\n")
    problems = p.problems(action)
    ensure(any(TURNS_ONE_WAY in m for m in problems),
           f"reviewed-action-required was allowed to grow: {problems}")


def _ratchet_both_ways() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _empty_scope(root)
        probe = Probe(root)
        _threshold_ratchet(probe)
        _reviewed_dispositions(probe)


def _pre_rename_field() -> None:
    """The renamed field does not linger: a stale `exception_ref` is an unknown field."""
    stale = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                      "status": "unreviewed", "exception_ref": "EX-000 in record.md"}}
    ensure(any("unknown debt field" in m for m in register().problems(stale)),
           "the pre-rename `exception_ref` field was accepted")


def _lifecycle_relation() -> None:
    """The §14 disposition lifecycle, asserted as a relation rather than restated."""
    permitted = [
        ("unreviewed", "reviewed-exception"),
        ("unreviewed", "reviewed-action-required"),
        ("reviewed-action-required", "reviewed-action-required"),
        ("reviewed-action-required", "reviewed-exception"),
        ("reviewed-exception", "reviewed-action-required"),
    ]
    # Nothing returns to `unreviewed`: that would say nobody had looked.
    refused = [
        ("reviewed-exception", "unreviewed"),
        ("reviewed-action-required", "unreviewed"),
    ]
    for old_s, new_s in permitted:
        ensure(permitted_transition(old_s, new_s), f"`{old_s}` -> `{new_s}` should be permitted")
    for old_s, new_s in refused:
        ensure(not permitted_transition(old_s, new_s),
               f"`{old_s}` -> `{new_s}` should be refused")
    for status in sorted(STATUSES):
        ensure(permitted_transition(status, status),
               f"`{status}` -> itself should be permitted")


def _lifecycle_applied() -> None:
    """The relation is actually APPLIED, not merely defined."""
    before = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                       "status": "reviewed-action-required",
                       "review_ref": "EX-000 in record.md"}}
    after = {"a.rs": dict(before["a.rs"], status="unreviewed")}
    ensure(any("does not permit" in m for m in check_transitions(before, after)),
           "a completed census was allowed back to `unreviewed`")
    ensure(not check_transitions(before, {"a.rs": dict(before["a.rs"],
                                                       status="reviewed-exception")}),
           "a permitted disposition transition was refused")
    # A unit that is not in the baseline is a new debt, not a transition.
    ensure(not check_transitions({}, after), "a newly registered file was judged as a transition")


PASS_LINE = (
    "module-size gate selftest: PASS (ratchet in both directions, empty scope, stale "
    "entries, the §14 disposition lifecycle and its refusals, the pre-rename "
    "`exception_ref` field, the one-shot upward baseline authorization, and the "
    "measurement correction that buys nothing; the register schema and its three "
    "baseline states are `_ratchet`'s selftest)"
)


def selftest() -> int:
    try:
        _ratchet_both_ways()
        _pre_rename_field()
        _lifecycle_relation()
        _lifecycle_applied()
    except SelftestFailure as failure:
        print(f"selftest FAIL: {failure}")
        return 1
    if selftest_baseline_growth() != 0:
        return 1
    print(PASS_LINE)
    return 0
