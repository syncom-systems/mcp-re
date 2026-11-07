# SPDX-License-Identifier: Apache-2.0
"""Selftest: the coverage verdict, and which workflows count as the merge path."""

from __future__ import annotations

from _merge_path.defects import Coverage, defects
from _merge_path.reach import pull_request_reach
from _merge_path.selftest_support import expect
from workflow_reader import parse

#: `(gated, covered, exempt, expected finding or None, label)`.
_COVERAGE_CASES = [
    ({"scripts/a.py"}, set(), {}, "runs only in scripts/local_gate.sh", "a control on no workflow"),
    ({"scripts/a.py"}, {"scripts/a.py"}, {}, None, "a control a workflow names"),
    ({"scripts/a.py"}, set(), {"scripts/a.py": "local by design"}, None, "an exempt control"),
    (set(), set(), {"scripts/gone.py": "stale"}, "scripts/local_gate.sh does not invoke it", "an exemption naming nothing"),
]

#: A filtered workflow must not count as coverage, and an unfiltered one must.
_REACH_CASES = [
    ("on:\n  pull_request:\n    branches: [main]\n", "every", "a pull_request trigger with no paths key"),
    ("on:\n  pull_request:\n    paths:\n      - 'src/**'\n", "filtered", "a paths key"),
    ("on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n", None, "a workflow no pull request starts"),
    ("on:\n  push:\n    paths:\n      - 'src/**'\n  pull_request:\n", "every", "a filter on push only"),
]


def _check_coverage_cases() -> None:
    for gated, covered, exempt, needle, label in _COVERAGE_CASES:
        found = defects(gated, Coverage(covered), exempt)
        if needle is None:
            expect(not found, f"refused {label}: {found}")
        else:
            expect(any(needle in entry for entry in found), f"accepted {label}")


def _check_filtered_only() -> None:
    """The two rules added after the sweep, each with the case that motivated it."""
    filtered = defects({"scripts/a.py"}, Coverage(set(), {"scripts/a.py"}), {})
    expect(
        any("`paths:`-filtered workflow" in entry for entry in filtered),
        "accepted a control named only by a filtered workflow",
    )
    expect(
        not any("runs only in scripts/local_gate.sh" in entry for entry in filtered),
        "a filtered-only control reported as local-only",
    )


def _check_platform_selftests() -> None:
    suite = "tools/verification/test_x.py"
    uncovered = defects(set(), Coverage(set()), {}, selftests={suite})
    expect(
        any("assurance-platform self-test" in entry for entry in uncovered),
        "accepted a self-test no unconditional workflow names",
    )
    covered = defects(set(), Coverage({suite}), {}, selftests={suite})
    expect(not covered, f"refused a covered self-test: {covered}")


def _check_pull_request_reach() -> None:
    for text, expected, why in _REACH_CASES:
        actual = pull_request_reach(parse(text))
        expect(actual == expected, f"{why} read as {actual!r}")


def check() -> None:
    _check_coverage_cases()
    _check_filtered_only()
    _check_platform_selftests()
    _check_pull_request_reach()
