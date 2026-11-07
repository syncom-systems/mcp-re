# SPDX-License-Identifier: Apache-2.0
"""Sharded runs compose into one verdict that no shard can fake.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from _mutation_lane_support import lane


def _compose(logs: dict[str, str], shards: int) -> int:
    import contextlib
    import io

    with tempfile.TemporaryDirectory() as scratch:
        for name, text in logs.items():
            (Path(scratch) / name).write_text(text)
        with contextlib.redirect_stdout(io.StringIO()):
            return lane.compose(Path(scratch), shards)


_SHARD_PASS = "verify-mutations: PASS — 3 probe(s), each turning a declared control red\nVERDICT: PASS\n"


def test_a_composition_of_passing_shards_passes():
    assert _compose({"shard-0.log": _SHARD_PASS, "shard-1.log": _SHARD_PASS}, 2) == 0


def test_unavailable_probes_are_named_apart_from_measured_passes():
    """A shard that skipped SDK probes passes, but the composed verdict line must say which
    probes were not measured, so the run cannot be read as complete."""
    import contextlib
    import io

    shard = (
        "  UNAVAILABLE M201: sdk_python matrix not built\n"
        "  UNAVAILABLE M305: sdk_typescript matrix not built\n"
        "verify-mutations: PASS — 4 probe(s), each turning a declared control red; "
        "2 UNAVAILABLE in this environment (M201, M305). The umbrella run measures those.\n"
        "VERDICT: PASS\n"
    )
    with tempfile.TemporaryDirectory() as scratch:
        (Path(scratch) / "shard-0.log").write_text(shard)
        (Path(scratch) / "shard-1.log").write_text(_SHARD_PASS)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert lane.compose(Path(scratch), 2) == 0
    summary = [line for line in out.getvalue().splitlines() if line.startswith("verify-mutations:")]
    assert summary == [
        "verify-mutations: PASS — all 2 shard(s) stated PASS; "
        "2 probe(s) UNAVAILABLE, not measured (M201, M305)"
    ]


def test_a_shard_that_measured_nothing_still_fails_the_composition():
    """Every probe in the shard UNAVAILABLE is that shard's VERDICT: UNAVAILABLE."""
    shard = "  UNAVAILABLE M201: sdk_python matrix not built\nVERDICT: UNAVAILABLE\n"
    assert _compose({"shard-0.log": shard, "shard-1.log": _SHARD_PASS}, 2) == 1


def test_a_shard_that_left_no_output_fails_the_composition():
    """A shard cancelled at its timeout uploads nothing; counting the files present would
    read that shard as never having been decided on."""
    assert _compose({"shard-0.log": _SHARD_PASS}, 2) == 1


def test_a_shard_that_stated_no_verdict_fails_the_composition():
    """A shard killed mid-run leaves its partial output and no verdict line."""
    assert _compose({"shard-0.log": _SHARD_PASS, "shard-1.log": "  ok   M1  T\n"}, 2) == 1


def test_a_shard_verdict_other_than_pass_fails_the_composition():
    for verdict in ("FAIL", "UNAVAILABLE", "NOT_REQUIRED"):
        assert _compose({"shard-0.log": _SHARD_PASS, "shard-1.log": f"VERDICT: {verdict}\n"}, 2) == 1


def test_a_shard_stating_two_verdicts_fails_the_composition():
    assert _compose({"shard-0.log": _SHARD_PASS + "VERDICT: FAIL\n"}, 1) == 1


def test_a_composition_of_no_shards_measured_nothing():
    assert _compose({}, 0) == 1
    assert _compose({"shard-0.log": _SHARD_PASS}, 0) == 1


def test_a_shard_the_scope_did_not_decide_on_fails_the_composition():
    assert _compose({"shard-0.log": _SHARD_PASS, "shard-1.log": _SHARD_PASS}, 1) == 1


def test_the_lanes_check_is_the_composition_and_it_runs_after_every_shard():
    """The merge-readiness gate reads the job named for the lane. It must be the one that
    composes, it must run whatever the shards did, and a shard must never carry that name."""
    workflow = (lane.REPO_ROOT / ".github/workflows/mutation-probe.yml").read_text()
    verdict = workflow[workflow.index("\n  verdict:\n"):]
    assert "name: V0 evidence self-test (mutation probes)" in verdict
    assert "if: always() && needs.scope.outputs.measure == 'true'" in verdict
    assert "--compose" in verdict and "--shards ${{ needs.scope.outputs.shard-count }}" in verdict
    probe = workflow[workflow.index("\n  probe:\n"):workflow.index("\n  verdict:\n")]
    assert "name: mutation probe shard ${{ matrix.shard }}" in probe
    assert "fail-fast: false" in probe
