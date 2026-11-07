# SPDX-License-Identifier: Apache-2.0
"""Selftest: every shape of one check that must NOT read as READY, and the attribution of a
shared job's failure."""

from __future__ import annotations

from _merge_readiness.tally import Tally
from _merge_readiness.verdict import FAILED, NOT_READY, READY, decide, skipped_by_itself

SHA = "a" * 40
UMBRELLA_JOB = "verification platform"
DEDICATED_JOB = "V0 evidence self-test (mutation probes)"


def _check(name: str, status: str, conclusion: str | None, head: str = SHA) -> dict:
    return {"name": name, "head_sha": head, "status": status, "conclusion": conclusion}


def _single_check_cases() -> list[tuple]:
    job = UMBRELLA_JOB
    return [
        (None, NOT_READY, "missing check"),
        (_check(job, "queued", None), NOT_READY, "queued"),
        (_check(job, "in_progress", None), NOT_READY, "in_progress"),
        (_check(job, "completed", None), NOT_READY, "null conclusion"),
        (_check(job, "completed", ""), NOT_READY, "empty conclusion"),
        (_check(job, "completed", "skipped"), NOT_READY, "skipped while required"),
        (_check(job, "completed", "cancelled"), NOT_READY, "cancelled measured nothing"),
        (_check(job, "completed", "neutral"), NOT_READY, "neutral"),
        (_check(job, "completed", "success", "b" * 40), NOT_READY, "green at another SHA"),
        (_check(job, "completed", "failure"), FAILED, "failure"),
        (_check(job, "completed", "timed_out"), FAILED, "timed_out"),
        (_check(job, "completed", "success"), READY, "the only ready shape"),
    ]


def _single_check(tally: Tally) -> None:
    required = {"test": [UMBRELLA_JOB]}
    for check, want, label in _single_check_cases():
        runs = {UMBRELLA_JOB: check} if check else {}
        got = decide(required, runs, SHA)[0]
        if got != want:
            tally.fail(f"{label}: wanted {want}, got {got}")


def _skipped(tally: Tally) -> None:
    """A deferring job is not a measuring one; a skipped ruleset check stays unsatisfied."""
    skipped = _check(DEDICATED_JOB, "completed", "skipped")
    misread = (
        not skipped_by_itself(skipped, SHA)
        or skipped_by_itself({**skipped, "head_sha": "b" * 40}, SHA)
        or skipped_by_itself({**skipped, "conclusion": "success"}, SHA)
        or skipped_by_itself(None, SHA)
    )
    tally.expect(not misread, "skipped_by_itself misread a check")
    ruleset = {"ruleset": {**skipped, "name": "ruleset"}}
    tally.expect(
        decide({"ruleset": ["ruleset"]}, ruleset, SHA)[0] == NOT_READY,
        "a skipped ruleset check read as satisfied",
    )


def _attribution(tally: Tally) -> None:
    """A shared job's failure must never be reported as a lane's own verdict."""
    umb, ded = UMBRELLA_JOB, DEDICATED_JOB
    red_umbrella = {umb: _check(umb, "completed", "failure")}

    # Only the umbrella runs this lane, and it went red: NOT_READY, never FAILED.
    state, rows = decide({"lean": [umb]}, red_umbrella, SHA, {umb})
    tally.expect(state == NOT_READY, f"an umbrella failure was attributed to a single lane: {state}")
    tally.expect(
        "not attributable" in rows[0][3],
        "the row does not say the umbrella's verdict is unattributable",
    )

    # A lane with its OWN job: that job's failure IS the lane's verdict.
    state, _ = decide({"mutation": [ded]}, {ded: _check(ded, "completed", "failure")}, SHA, {umb})
    tally.expect(state == FAILED, f"a dedicated job's failure did not read as FAILED: {state}")

    # The umbrella is red, but the lane's own job passed: satisfied, because a lane is
    # satisfied by ANY job that actually measured it.
    both = {**red_umbrella, ded: _check(ded, "completed", "success")}
    state, _ = decide({"mutation": [ded, umb]}, both, SHA, {umb})
    tally.expect(state == READY, f"a passing dedicated job was overridden by a red umbrella: {state}")

    # And the umbrella's SUCCESS does cover a lane it contains.
    state, _ = decide({"lean": [umb]}, {umb: _check(umb, "completed", "success")}, SHA, {umb})
    tally.expect(state == READY, f"a successful umbrella did not satisfy a lane it runs: {state}")


def _fallback(tally: Tally) -> None:
    """The fallback authority answers the SAME four conditions. A ruleset check that is
    queued must not read as READY just because the manifest asked for nothing."""
    name = "Bazel build + test"
    fallback = {name: [name]}
    tally.expect(
        decide(fallback, {name: _check(name, "queued", None)}, SHA)[0] == NOT_READY,
        "a queued ruleset check read as ready under the fallback authority",
    )
    tally.expect(
        decide(fallback, {}, SHA)[0] == NOT_READY,
        "a missing ruleset check read as ready under the fallback authority",
    )


def run(tally: Tally) -> None:
    _single_check(tally)
    _skipped(tally)
    _attribution(tally)
    _fallback(tally)
