# SPDX-License-Identifier: Apache-2.0
"""The lane reaches the SDK roots, and a tree that did not build is not red.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect

from _mutation_lane_support import UNITS, expect_manifest_error, lane, make_probe


#
# Every case here is a way the extension could report redness it had not measured. The
# lane's rule does not change per ecosystem -- a control that did not run is not red --
# so each Rust case above has a counterpart the moment a second runner can be selected.


def _sdk_unit(prefix: str) -> tuple[str, dict]:
    """A real registered unit of that ecosystem, with a symbol of it, or skip the case.

    Read from the registry rather than invented: a fixture unit would prove the lane can
    run a shape nothing declares, which is the opposite of the property.
    """
    for uid, unit in sorted(UNITS.items()):
        if uid.startswith(prefix) and unit.get("tested_symbols"):
            return uid, unit
    raise AssertionError(f"no registered {prefix} unit with controls")


def test_a_python_unit_resolves_its_project_and_carries_its_ecosystem():
    """Resolution was never the blocker, and this pins that so the next reader does not
    re-remove a refusal that does not exist: `test_project_for` is ecosystem-aware and
    answers `sdk/python` here. What the battery needs from `declared_battery` is the
    ECOSYSTEM, because that is what decides how the selection is run."""
    from _ecosystems import test_project_for

    uid, unit = _sdk_unit("sdk_python.")
    assert test_project_for(unit), "the platform resolves a project for an SDK unit"
    probe = make_probe(unit=uid, expect_red=[unit["tested_symbols"][0]])
    package, grouped, _gates, eco = lane.declared_battery(UNITS, probe, "p")
    assert package, "a python unit must resolve a project"
    assert eco is lane.PYTHON
    assert "pytest" in grouped, grouped


def test_a_typescript_unit_resolves_a_project_too():
    uid, unit = _sdk_unit("sdk_typescript.")
    probe = make_probe(unit=uid, expect_red=[unit["tested_symbols"][0]])
    package, grouped, _gates, eco = lane.declared_battery(UNITS, probe, "p")
    assert package, "a typescript unit must resolve a project"
    assert eco is lane.TYPESCRIPT
    assert "vitest" in grouped, grouped


def test_an_undeclared_control_is_still_refused_on_an_sdk_unit():
    """The declared-battery rule is the lane's, not any runner's. It must not have been lost
    with the ecosystem dispatch."""
    uid, _unit = _sdk_unit("sdk_python.")
    expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, make_probe(unit=uid, expect_red=["pytest#tests/nope.py::not_declared"]), "p"
        ),
        "an undeclared control must be refused whatever the ecosystem",
    )


def test_every_ecosystem_can_say_the_tree_did_not_build():
    """A weakening routinely breaks the build. If no marker matched for an ecosystem, that
    state would parse as zero results and then as controls that never ran -- which the
    adjudicator reports as a MEASUREMENT FAILURE, so it is not a false green, but it makes
    every probe over that ecosystem permanently unmeasurable."""
    assert lane._BAZEL_BUILT, "RUST names no exit status for a build that completed"
    assert 1 not in lane._BAZEL_BUILT, "Bazel's failed-build status read as a completed build"
    for eco in (lane.PYTHON, lane.TYPESCRIPT):
        assert lane._DID_NOT_BUILD.get(eco), f"{eco.name} names no did-not-build marker"


def test_a_tree_that_did_not_build_is_not_red_in_any_ecosystem():
    """The false green this guards. If a broken tree read as `FAILED` for every control, a
    probe would be satisfied by BREAKING the tree rather than by weakening the property,
    and the redness would measure the compiler instead of the claim. Same rule, same
    reason, as a gate control that the weakening DELETED."""
    for eco, marker, status in (
        (lane.RUST, "error[E0432]: unresolved import", 1),
        (
            lane.RUST,
            "ERROR: /t/mcp-re-core/BUILD.bazel:8:16: Compiling Rust rlib mcp_re_core (31 files) "
            "failed: (Exit 1): process_wrapper failed",
            1,
        ),
        (lane.RUST, "ERROR: Build did NOT complete successfully", 1),
        (lane.PYTHON, "ERROR collecting tests/test_mtls.py", 2),
        (lane.TYPESCRIPT, "Failed to load url ./transport", 1),
    ):
        assert lane._did_not_build(eco, marker, status), eco.name
        assert not lane._did_not_build(eco, "everything is fine", 0), eco.name


def test_an_unreadable_report_is_not_red():
    """`parse_results` raises when the runner collected cases and the reader understood
    none of them. That is the lane's own blindness; presenting it as a red battery would
    satisfy the probe with a parsing bug."""
    body = inspect.getsource(lane.run_battery)
    assert "except ReportUnreadable" in body
    assert body.index("except ReportUnreadable") < body.index("return True, results")


def test_a_failed_test_is_not_a_tree_that_did_not_build():
    """The other direction of the same rule. A weakened control that compiled, ran and
    objected is the red this lane exists to see; Bazel reports it as a failed TEST, with
    none of the build-failure markers, and it must reach the adjudicator as `FAILED`."""
    failed_test = (
        "test a::tests::one ... FAILED\n"
        "//mcp-re-core:mcp_re_core_test                 FAILED in 0.1s\n"
        "Executed 1 out of 1 test: 1 fails locally.\n"
    )
    assert not lane._did_not_build(lane.RUST, failed_test, 3)


def test_a_rust_build_is_judged_by_bazels_exit_status_not_by_its_text():
    """One `bazel test` can hold an abandoned build attempt and the one that replaced it, so
    no line of its output is a statement about the whole command. Only the status is."""
    abandoned = (
        "ERROR: /t/external/redis/BUILD.bazel:15:13: Compiling Rust rlib redis v1.7.1 "
        "(115 files) failed: Lost inputs no longer available remotely: libarc_swap.rlib\n"
        "ERROR: Build did NOT complete successfully\n"
    )
    for status in (0, 3, 4):
        assert not lane._did_not_build(lane.RUST, abandoned, status), status
    for status in (1, 2, 8, 36, 37, 39):
        assert lane._did_not_build(lane.RUST, "", status), status


def test_every_rust_target_kind_runs_through_the_one_seam():
    """One declaration of how a label runs, and this lane must not hold a second.

    An earlier version of this lane built its own argv and knew fewer target shapes than
    the test lane did; a battery in an unknown shape was refused by the runner with a
    message that was not a build failure, so the lane reported a MEASUREMENT FAILURE and
    blamed a probe whose weakening works. Every kind the registry can name — a unit-test
    flavor, an integration target, a binary's tests, a doctest target — goes through
    `_ecosystems.test_argv`.
    """
    from _ecosystems import RUST, test_argv

    for label in (
        "//mcp-re-proxy:proxy_unit_test",
        "//mcp-re-http-profile:full_profile_test",
        "//mcp-re-client:mcp_re_client_cli_test",
        "//mcp-re-http-profile:mcp_re_http_profile_doc_test",
    ):
        argv = test_argv(RUST, label, ["sym"])
        assert argv[:3] == ["bazel", "test", label], argv
    # And the lane asks the seam rather than answering for itself.
    assert "target_argv(" not in inspect.getsource(lane.run_battery)
