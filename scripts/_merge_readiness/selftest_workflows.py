# SPDX-License-Identifier: Apache-2.0
"""Selftest: how required checks are derived from the workflows."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _merge_readiness.derivation import (
    UMBRELLA,
    checks_for_lanes,
    lane_scripts,
    pull_request_workflows,
    workflow_jobs,
    workflows_dir,
)
from _merge_readiness.errors import Undecidable
from _merge_readiness.tally import Tally

import _registries  # noqa: E402

_PROSE = (
    "jobs:\n"
    "  someJob:\n"
    "    name: a job that only TALKS about the umbrella\n"
    "    steps:\n"
    "      # tools/verification/verify --manifests is what enforces this\n"
    "      - run: echo hello\n"
)
_REAL = _PROSE.replace("      - run: echo hello", "      - run: tools/verification/verify --gate")
_MUTATION_JOB = "V0 evidence self-test (mutation probes)"


def _unrunnable_lane(tally: Tally) -> None:
    """A required lane that no job runs must refuse, not resolve to an empty requirement."""
    try:
        checks_for_lanes({"nosuchlane"}, {})
    except Undecidable:
        return
    tally.fail("an unrunnable lane resolved instead of refusing")


def _umbrella_jobs(body: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "probe.yml").write_text(body, encoding="utf-8")
        with workflows_dir(Path(tmp)):
            return {name for _wf, name, invoked in workflow_jobs() if UMBRELLA in invoked}


def _invocations_not_mentions(tally: Tally) -> None:
    """COUNT INVOCATIONS, NOT MENTIONS. A comment that NAMES the umbrella must not make its
    job look like it RUNS the umbrella. This is not hypothetical: a comment in `ci.yml`
    explaining that `tools/verification/verify --manifests` enforces N1 made the cargo job
    resolve as an umbrella job, and every lane was attributed to it. Both directions,
    because a control that only refuses prose could refuse the real invocation too."""
    for label, body, expect_umbrella in (("a comment does not invoke", _PROSE, False),
                                         ("a run: line does invoke", _REAL, True)):
        found = _umbrella_jobs(body)
        if bool(found) != expect_umbrella:
            tally.fail(f"{label}: umbrella jobs resolved to {found}")


def _umbrella_covers_lanes(tally: Tally) -> None:
    """The umbrella satisfies a lane whose own script no workflow names literally."""
    resolved = checks_for_lanes({"test", "mutation"}, lane_scripts())
    for lane in ("test", "mutation"):
        tally.expect(lane in resolved, f"lane '{lane}' resolved to no check")


def _pre_merge_requirements(tally: Tally) -> None:
    """PRE-MERGE REQUIREMENTS ARE WHAT A PULL REQUEST STARTS. The complete run starts on
    schedule and dispatch only, so a lane that only it executes is deferred, never "missing"
    (which would block every merge) and never "satisfied" (which would claim a measurement)."""
    for changed in ({"MODULE.bazel", "MODULE.bazel.lock", _registries.relative("toolchains")},
                    {"tools/verification/verify"}, {"mcp-re-core/src/lib.rs"}):
        started = pull_request_workflows(changed)
        if "verification.yml" in started or "pre-merge.yml" not in started:
            tally.fail(f"a pull request changing {sorted(changed)} started {sorted(started)}")
        resolved = checks_for_lanes({"test", "lean", "verus"}, lane_scripts(), started)
        if any(resolved[lane] for lane in ("test", "lean", "verus")):
            tally.fail(f"a lane only the complete run executes was required before merge: {resolved}")
    tally.expect(
        not pull_request_workflows({"MODULE.bazel"}) & {"mutation-probe.yml"},
        "a MODULE.bazel change started the mutation probe, whose filter does not name it",
    )
    tally.expect(
        "mutation-probe.yml" in pull_request_workflows({"mcp-re-core/src/lib.rs"}),
        "a probed source change did not start the mutation probe",
    )
    bounded = checks_for_lanes({"mutation"}, lane_scripts(), {"mutation-probe.yml"})["mutation"]
    tally.expect(
        bounded == [_MUTATION_JOB],
        "the mutation lane did not resolve to its bounded pre-merge job",
    )


def _paths_filter_cases(tally: Tally) -> None:
    """paths-ignore: a pull request starts the workflow unless EVERY changed file is ignored."""
    cases = (
        ("only ignored files", "paths-ignore:\n      - 'docs/**'", {"docs/a.md"}, False),
        ("one non-ignored file", "paths-ignore:\n      - 'docs/**'", {"docs/a.md", "src/a.rs"}, True),
        ("a paths filter that matches", "paths:\n      - 'src/**'", {"src/a.rs"}, True),
        ("a paths filter that does not", "paths:\n      - 'src/**'", {"docs/a.md"}, False),
    )
    for label, filt, changed, expect in cases:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "w.yml").write_text(
                f"name: w\non:\n  pull_request:\n    {filt}\njobs:\n  j:\n    steps:\n      - run: true\n",
                encoding="utf-8")
            with workflows_dir(Path(tmp)):
                got = "w.yml" in pull_request_workflows(changed)
        if got != expect:
            tally.fail(f"pull_request_workflows, {label}: started={got}")


def run(tally: Tally) -> None:
    _unrunnable_lane(tally)
    _invocations_not_mentions(tally)
    _umbrella_covers_lanes(tally)
    _pre_merge_requirements(tally)
    _paths_filter_cases(tally)
