# SPDX-License-Identifier: Apache-2.0
"""The mutation lane's own false-green catalogue.

The lane exists to prove that a claimed conjunct is load-bearing. Every way it could report
that without having proved it is a case below:

  * a probe whose anchor matches zero or two sites has not identified the check it claims
    to have broken;
  * a probe expecting a control the unit does not DECLARE would prove something about a
    test that is not evidence for the theorem;
  * a control that NEVER RAN counted as red in the first version of this lane, so a
    weakening that stopped a test from being reported at all satisfied the probe;
  * a control matched by bare symbol could be satisfied by a same-named test in a target
    the probe never intended to touch;
  * a probe with no expectations at all asserts nothing;
  * a weakened tree that does not compile has measured nothing, and must not read as
    "the controls held".

Run: python3 tools/verification/test_mutation_lane.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _mutation_lane_cases_adjudication  # noqa: E402
import _mutation_lane_cases_builds  # noqa: E402
import _mutation_lane_cases_closure  # noqa: E402
import _mutation_lane_cases_compose  # noqa: E402
import _mutation_lane_cases_gates  # noqa: E402
import _mutation_lane_cases_libtest  # noqa: E402
import _mutation_lane_cases_probes  # noqa: E402
import _mutation_lane_cases_registry  # noqa: E402
from _mutation_lane_support import lane  # noqa: E402

CASE_MODULES = (
    _mutation_lane_cases_adjudication,
    _mutation_lane_cases_builds,
    _mutation_lane_cases_closure,
    _mutation_lane_cases_compose,
    _mutation_lane_cases_gates,
    _mutation_lane_cases_libtest,
    _mutation_lane_cases_probes,
    _mutation_lane_cases_registry,
)


def test_a_passing_control_is_not_red():
    probe = _mutation_lane_cases_registry.make_probe(expect_red=["tests/t#a"])
    assert lane.adjudicate(probe, {"tests/t#a": "ok"}) == ([], [])


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
