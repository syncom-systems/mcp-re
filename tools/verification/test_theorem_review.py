# SPDX-License-Identifier: Apache-2.0
"""The specification-gap control — ADR-MCPRE-059 §14.1, §14.3, §14.7.

**The essential negative control, and the reason this phase exists:** weaken a theorem's
statement while its proof stays green, and specification review goes dirty. If that fails,
a green prover can carry a stale approval of a claim nobody re-read, which is the exact
substitution the theorem layer was built to refuse.

Everything else here keeps that control from being satisfied vacuously:

  * the two axes must be SEPARATE — restating a claim must not move a unit fingerprint, and
    editing source must not move a theorem fingerprint. Either leak collapses them into the
    single green/red bit §14.7 forbids;
  * a premise weakened three theorems down must reach the claim on top;
  * relaxing `review_requirement` must dirty the review, or the one edit that lowers the
    bar is the one edit nothing notices;
  * an absent, malformed, or forbidden-key review record must never read as an approval;
  * establishment must fail when ANY axis fails, so no axis can carry the others.

Run: python3 tools/verification/test_theorem_review.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _theorem_review_cases_claim  # noqa: E402
import _theorem_review_cases_records  # noqa: E402
import _theorem_review_cases_establishment  # noqa: E402
import _theorem_review_cases_premises  # noqa: E402
import _theorem_review_cases_axes  # noqa: E402
import _theorem_review_cases_ledger  # noqa: E402
import _theorem_review_cases_roots  # noqa: E402
import _theorem_review_cases_closures  # noqa: E402
from _theorem_review_support import fingerprints, registry  # noqa: E402
from _review import UNREVIEWED, derive_review_state  # noqa: E402

CASE_MODULES = (
    _theorem_review_cases_claim,
    _theorem_review_cases_records,
    _theorem_review_cases_establishment,
    _theorem_review_cases_premises,
    _theorem_review_cases_axes,
    _theorem_review_cases_ledger,
    _theorem_review_cases_roots,
    _theorem_review_cases_closures,
)


# --- records that must not read as approvals ---------------------------------------


def test_an_absent_record_is_unreviewed():
    current = fingerprints(registry())["THM-0001"]
    assert derive_review_state(current, None)[0] == UNREVIEWED


def collect_cases() -> dict:
    """Every `test_*` callable here and in the case modules, by name."""
    cases = {name: fn for name, fn in globals().items() if name.startswith("test_")}
    for module in CASE_MODULES:
        cases.update(
            {name: fn for name, fn in vars(module).items() if name.startswith("test_")}
        )
    return cases


def run() -> int:
    failures = 0
    for name, fn in sorted(collect_cases().items()):
        if not callable(fn):
            continue
        try:
            fn()
            print(f"ok   {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
