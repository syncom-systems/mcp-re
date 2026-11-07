"""Selftest properties P5-P9 and P12: the register, the lifecycle, UC-3 and empty scope."""

from __future__ import annotations

from _unit_closure.register import (
    check_new_debt,
    check_transitions,
    empty_scope_is_failure,
    permitted_transition,
)
from _unit_closure.selftest_support import ENTRY, SPLIT, Verdicts, problems_of, run, unit

_DOCS = {"docs/d.md": "REV-1"}


def p5_entry_scope(v: Verdicts) -> None:
    """An entry silences its own path and nothing else."""
    p = problems_of({**SPLIT, **_DOCS}, [unit("u.sp", "c/src/sp/mod.rs")], ENTRY)
    v.case("P5 entry silences its own path", p, None)
    p = problems_of(
        {
            **SPLIT,
            **_DOCS,
            "c/src/sp/mod.rs": "mod rotation;\nmod mint;\npub fn advance() {}\n",
            "c/src/sp/mint.rs": "",
        },
        [unit("u.sp", "c/src/sp/mod.rs")],
        ENTRY,
    )
    v.case("P5 a second escape is still red", p, "c/src/sp/mint.rs")


def p6_register_may_only_shrink(v: Verdicts) -> None:
    """The register may not outlive what it answers."""
    p = problems_of(
        {**SPLIT, **_DOCS},
        [unit("u.sp", "c/src/sp/mod.rs", "c/src/sp/rotation.rs")],
        ENTRY,
    )
    v.case("P6 resolved entry must be removed", p, "must be removed, not left standing")


def p7_out_of_cone_needs_reason(v: Verdicts) -> None:
    """`reviewed-out-of-cone` is its reason; without one the disposition says nothing."""
    reasonless = {k: {f: x for f, x in e.items() if f != "reason"} for k, e in ENTRY.items()}
    p = problems_of({**SPLIT, **_DOCS}, [unit("u.sp", "c/src/sp/mod.rs")], reasonless)
    v.case("P7 out-of-cone needs a reason", p, "without a `reason`")


def p8_nothing_returns_to_unreviewed(v: Verdicts) -> None:
    for old, new, want in (
        ("reviewed-attached", "unreviewed", False),
        ("reviewed-out-of-cone", "unreviewed", False),
        ("unreviewed", "reviewed-attached", True),
        ("reviewed-attached", "reviewed-out-of-cone", True),
    ):
        if permitted_transition(old, new) is not want:
            v.fail(f"SELFTEST FAILED [P8]: `{old}` -> `{new}` should be {want}")
    moved = {
        "x.rs": {"path": "x.rs", "rule": "UC-1", "baseline_sha": "0", "status": "unreviewed"},
    }
    before = {
        "x.rs": {"path": "x.rs", "rule": "UC-1", "baseline_sha": "0",
                 "status": "reviewed-attached"},
    }
    v.case("P8 transition refused", check_transitions(before, moved), "does not permit")


def p9_uc3_admits_no_new_debt(v: Verdicts) -> None:
    v.case(
        "P9 new drift may not be registered",
        check_new_debt(ENTRY, {"c/src/sp/rotation.rs"}),
        "UC-3 admits no new debt",
    )
    v.case("P9 an old path may be registered", check_new_debt(ENTRY, {"other.rs"}), None)


def p12_not_self_satisfying(v: Verdicts) -> None:
    """The gate is not self-satisfying."""
    if not empty_scope_is_failure(0, 12):
        v.fail("SELFTEST FAILED [P12]: zero units must not be a pass")
    if not empty_scope_is_failure(114, 0):
        v.fail("SELFTEST FAILED [P12]: zero walked files must not be a pass")
    if empty_scope_is_failure(1, 1):
        v.fail("SELFTEST FAILED [P12]: a real run must not be refused")
    _, walked, units = run(SPLIT, [], {})
    if (units, walked) != (0, 0):
        v.fail(f"SELFTEST FAILED [P12]: an empty unit table walked {walked} files in {units}")


ALL = (
    p5_entry_scope,
    p6_register_may_only_shrink,
    p7_out_of_cone_needs_reason,
    p8_nothing_returns_to_unreviewed,
    p9_uc3_admits_no_new_debt,
    p12_not_self_satisfying,
)
