# SPDX-License-Identifier: Apache-2.0
"""The exit code CI reads: which gate aggregates count as a pass."""

from __future__ import annotations

from _load_tool import load_tool

verify_cli = load_tool("verify", "verify_cli")


def test_only_pass_exits_zero_under_gate():
    """FV-01 at the exit-code boundary: a SKIPPED or NOT_REQUIRED lane must never count
    toward a pass, and INCOMPLETE is exactly the aggregate those produce."""
    assert verify_cli.gate_exit_code("PASS", True) == 0
    assert verify_cli.gate_exit_code("FAIL", True) == 1
    assert verify_cli.gate_exit_code("INCOMPLETE", True) == 1


def test_report_only_mode_does_not_fail_an_unresolved_state():
    """What report mode withholds, and it is not the same as what it used to withhold.

    The claim this protects is that an honestly unresolved state must not fail ordinary
    development — the same reason `review --root-completeness` is report-only. INCOMPLETE
    is that state: no required lane produced formal evidence, which is a legitimate place
    to be while working and is not a place to merge from.
    """
    assert verify_cli.gate_exit_code("PASS", False) == 0
    assert verify_cli.gate_exit_code("INCOMPLETE", False) == 0


def test_report_only_mode_still_reports_a_measured_failure():
    """The half the claim above was over-broad about.

    This asserted that report mode never fails the build, for ANY aggregate. "Not
    authoritative" is a statement about what a PASS is worth, not a licence to report a
    failure as success — and a FAIL is not an unresolved state, it is a measured one.
    Anything reading the status rather than the verdict line read a failed lane as a pass,
    and something did.
    """
    assert verify_cli.gate_exit_code("FAIL", False) == 1
