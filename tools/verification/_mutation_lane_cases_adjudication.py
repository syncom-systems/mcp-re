# SPDX-License-Identifier: Apache-2.0
"""A control that never ran is not red, and a test is identified by target plus symbol.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect

from _mutation_lane_support import UNITS, expect_manifest_error, lane, make_probe


def test_a_control_that_never_reported_is_not_red():
    """The defect this lane shipped with. `results.get(name, "never ran") != "ok"` made an
    ABSENT result satisfy the probe, so a weakening that stopped a test from being reported
    at all read as "the control caught it". The lane cannot conclude anything about a check
    from a test it did not watch run."""
    probe = make_probe(expect_red=["tests/t#a", "tests/t#b"])
    missing, red = lane.adjudicate(probe, {})
    assert missing == ["tests/t#a", "tests/t#b"]
    assert red == []


def test_a_partially_reported_expectation_is_still_a_measurement_failure():
    """One control failing does not excuse another never executing: the probe named both,
    and the lane must say it could not measure one of them."""
    probe = make_probe(expect_red=["tests/t#a", "tests/t#b"])
    missing, red = lane.adjudicate(probe, {"tests/t#a": "FAILED"})
    assert missing == ["tests/t#b"]
    assert red == ["tests/t#a"]


def test_an_ignored_control_is_not_a_red_one():
    """An `#[ignore]`d test printed a line but did not execute. Reading it as red is the
    same false green one level down — the case `verify-tests` already catches."""
    probe = make_probe(expect_red=["tests/t#a"])
    missing, red = lane.adjudicate(probe, {"tests/t#a": "ignored"})
    assert missing == []
    assert red == []


def test_main_reports_absence_as_measurement_failure_and_not_as_success():
    body = inspect.getsource(lane.main)
    assert "MEASUREMENT FAILURE" in body
    assert "missing, red = adjudicate(probe, results)" in body


def test_main_reports_a_skipped_control_as_measurement_failure_not_as_a_finding():
    """The 2026-11-01 M213 case: the mTLS controls were skipped (no `cryptography` for the
    material generator), and the lane said the conjunct was NOT load-bearing. A skipped
    control did not run; the probe still fails, with the measurement named as the cause."""
    body = inspect.getsource(lane.main)
    skip_arm = body.index('if not red and skipped:')
    assert body.index('results.get(n) == "ignored"') < skip_arm
    assert skip_arm < body.index("is NOT load-bearing")
    assert "were reported SKIPPED" in body[skip_arm:body.index("is NOT load-bearing")]


def test_a_same_named_test_in_another_target_does_not_satisfy_a_probe():
    """Test identity here is target + symbol, and this is exactly where flattening bites:
    two integration targets may each hold `body_tamper_fails_closed`, and a probe about the
    request floor must not be satisfied by the response one going red."""
    probe = make_probe(expect_red=["//mcp-re-http-profile:proof_path_test#body_tamper_fails_closed"])
    observed = {"//mcp-re-http-profile:full_profile_test#body_tamper_fails_closed": "FAILED"}
    missing, red = lane.adjudicate(probe, observed)
    assert red == []
    assert missing == ["//mcp-re-http-profile:proof_path_test#body_tamper_fails_closed"]


def test_run_battery_keys_results_by_target_and_symbol():
    assert 'results[f"{target}#{name}"]' in inspect.getsource(lane.run_battery)


def test_every_registered_expectation_carries_its_target():
    """A bare symbol in the registry would be unmatchable against the target-qualified
    results, so this is both an identity rule and a liveness one.

    WHICH TARGETS ARE RUNNABLE IS THE ECOSYSTEM'S ANSWER, asked here rather than kept as a
    list. A literal list of target spellings kept here would drift behind the ecosystems —
    the first expectation in a new form would be refused by the lane's own test while the
    lane ran it correctly.
    `gate#` is not any ecosystem's target: it is this lane's own control form, resolved by
    `run_gates` rather than by a test runner, so it is named beside them.
    """
    from _ecosystems import ECOSYSTEMS, valid_target

    for probe in lane.load_probes():
        for name in probe["expect_red"]:
            assert "#" in name, (probe["id"], name)
            target, _, symbol = name.partition("#")
            assert symbol, (probe["id"], name)
            runnable = name.startswith("gate#") or any(
                valid_target(eco, target) for eco in ECOSYSTEMS
            )
            assert runnable, (probe["id"], name)


def test_a_doctest_control_may_not_be_expected_to_go_red():
    """A doctest target's members are compile-fail controls; no runtime weakening moves one,
    so a probe naming it could never be satisfied honestly."""
    expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS,
            make_probe(
                expect_red=[
                    "//mcp-re-http-profile:mcp_re_http_profile_doc_test"
                    "#verified_response::bound::VerifiedMcpResponse"
                ]
            ),
            "p",
        ),
        "a doctest control must be refused",
    )
