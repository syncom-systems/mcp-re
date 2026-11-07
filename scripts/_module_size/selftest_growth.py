# SPDX-License-Identifier: Apache-2.0
"""Selftest of the one-shot upward-baseline authorization, through every way it is refused."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _module_size.growth import Ledger, check_baseline_growth, growth_authorization_line
from _module_size.measure import register
from _module_size.selftest_support import REL_BIG as REL, SelftestFailure, ensure

BEFORE = {REL: {"path": REL, "baseline_prod_loc": 442, "baseline_sha": "x",
                "status": "unreviewed"}}
AT_454 = {REL: 454}


def entry(**over) -> dict[str, dict]:
    base = {"path": REL, "baseline_prod_loc": 454, "baseline_sha": "x",
            "status": "reviewed-exception", "review_ref": "EX-000 in record.md",
            "growth_from_prod_loc": 442, "growth_ref": "GR-000 in record.md"}
    base.update(over)
    return {REL: base}


def _refusals(root: Path) -> None:
    cases: list[tuple[str, dict[str, dict], dict[str, int], str]] = [
        # Raising the number with nothing else is the whole defect, in one line.
        ("a bare raised baseline", entry(growth_from_prod_loc=None, growth_ref=None),
         AT_454, "no growth authorization"),
        # Headroom: 442 -> 600 would buy 146 unreviewed lines from one review.
        ("headroom above the measured file", entry(baseline_prod_loc=600), {REL: 454},
         "never headroom"),
        # A unit already owed a decomposition may not grow while owing it.
        ("growth under reviewed-action-required",
         entry(status="reviewed-action-required"), AT_454, "kept it INTACT"),
        # The one-shot property: an authorization written for an earlier transition.
        ("a spent authorization reused", entry(growth_from_prod_loc=400), AT_454,
         "does not authorize the next"),
        # The record must be about THIS transition, not about growth in general.
        ("a record not naming this exact transition",
         entry(growth_ref="GR-001 in absent.md"), AT_454,
         "must authorize this exact transition"),
        # Half an authorization is not one.
        ("growth_ref with no transition", entry(growth_from_prod_loc=None), AT_454,
         "must appear together"),
        ("a transition with no record", entry(growth_ref=None), AT_454,
         "must appear together"),
    ]
    for name, current, meas, needle in cases:
        current[REL] = {k: v for k, v in current[REL].items() if v is not None}
        got = check_baseline_growth(current, Ledger(BEFORE, meas, root))
        ensure(any(needle in p for p in got), f"{name} was not refused ({needle!r} absent): {got}")

    # A spent authorization must not linger once the file has shrunk back past it.
    settled = {REL: dict(entry()[REL], baseline_prod_loc=440)}
    ensure(any("paid back" in p for p in
               check_baseline_growth(settled, Ledger({REL: dict(settled[REL])}, {REL: 440}, root))),
           "an authorization at or above the current baseline lingered")


def _authorized(root: Path) -> None:
    # Fully authorized: every condition met, and it passes.
    got = check_baseline_growth(entry(), Ledger(BEFORE, AT_454, root))
    ensure(not got, f"a fully authorized one-shot growth was refused: {got}")

    # ...and having been spent, it authorizes nothing further. `origin/main` now holds
    # 454, so the SAME entry raised again is a second transition with a stale pair.
    spent = {REL: dict(entry()[REL], baseline_prod_loc=466)}
    ensure(any("does not authorize the next" in p for p in
               check_baseline_growth(spent, Ledger(entry(), {REL: 466}, root))),
           "a merged authorization authorized a second increase")


def _correction_refusals(root: Path, bare: dict[str, dict]) -> None:
    """The measurement correction buys nothing, so each way it could buy something is shown
    refused."""
    no_auth = "no growth authorization"
    # It cannot travel with an edit to the file it re-baselines.
    ensure(any(no_auth in p for p in
               check_baseline_growth(bare, Ledger(BEFORE, AT_454, root, lambda _r: False))),
           "a changed file was re-baselined as a measurement correction")
    # A path git cannot answer for is not an unchanged path.
    ensure(any(no_auth in p for p in
               check_baseline_growth(bare, Ledger(BEFORE, AT_454, root, lambda _r: None))),
           "an unanswerable path was re-baselined as a correction")
    # It grants no headroom: the new baseline must EQUAL the measurement.
    roomy = {REL: dict(bare[REL], baseline_prod_loc=600)}
    ensure(any(no_auth in p for p in
               check_baseline_growth(roomy, Ledger(BEFORE, AT_454, root, lambda _r: True))),
           "a measurement correction granted headroom")


def _correction_accepted(root: Path, bare: dict[str, dict]) -> None:
    # An unchanged file pinned at exactly its measured size: accepted, and the status is
    # NOT required to be `reviewed-exception` — correcting a number is not a review.
    plain = {REL: dict(bare[REL], status="unreviewed")}
    del plain[REL]["review_ref"]
    got = check_baseline_growth(plain, Ledger(BEFORE, AT_454, root, lambda _r: True))
    ensure(not got, f"a measurement correction on an unchanged file was refused: {got}")

    # A shrink needs no authorization at all; the ratchet already permits it.
    shrink = {REL: {"path": REL, "baseline_prod_loc": 430, "baseline_sha": "x",
                    "status": "unreviewed"}}
    ensure(not check_baseline_growth(shrink, Ledger(BEFORE, {REL: 430}, root)),
           "a shrinking baseline was made to justify itself")

    # The growth fields are part of the schema, not unknown fields.
    problems = register(root).problems(entry())
    ensure(not problems,
           f"the growth authorization fields were rejected as unknown: {problems}")


def _assertions(root: Path) -> None:
    (root / "record.md").write_text(
        "# EX-000, a §14 record\n\n"
        f"{growth_authorization_line(REL, 442, 454)}\n"
    )
    _refusals(root)
    _authorized(root)
    # The measurement correction is the OTHER way to a raised baseline — and the narrow
    # one. Refusals first, again, because it buys nothing and must be shown to buy nothing.
    bare = {REL: {k: v for k, v in entry()[REL].items()
                  if k not in ("growth_from_prod_loc", "growth_ref")}}
    _correction_refusals(root, bare)
    _correction_accepted(root, bare)


def selftest_baseline_growth() -> int:
    """The one-shot upward-baseline authorization, asserted through every way it is refused.

    The hole this closes was invisible precisely because raising `baseline_prod_loc` looked
    like bookkeeping, so the positive case is asserted LAST: every refusal first, then the
    one arrangement that passes, so a rule that accepted everything could not read as green.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp:
            _assertions(Path(tmp))
    except SelftestFailure as failure:
        print(f"selftest FAIL: {failure}")
        return 1
    return 0
