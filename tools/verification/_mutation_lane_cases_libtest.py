# SPDX-License-Identifier: Apache-2.0
"""The Rust battery reads libtest's own record and nothing else.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from _mutation_lane_support import lane


_CONTROL = "http_profile_serve::retention::outcome::tests::a_failed_completion_is_not_accounted_for"
_LABEL = "//mcp-re-proxy:proxy_unit_test"


def _run_rust_battery(stdout="", stderr="", logfile=None, returncode=0):
    """`run_battery` over one Rust target with `subprocess.run` replaced.

    `logfile` is what libtest's own record contains (None = the harness wrote none);
    `stdout`/`stderr` are what Bazel printed, which the lane must not read results from.
    """
    def fake_run(argv, **_kwargs):
        path = [a for a in argv if a.startswith("--test_arg=--logfile=")]
        assert path, "the Rust battery must ask libtest for its own record"
        if logfile is not None:
            Path(path[0].split("=", 2)[2]).write_text(logfile)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    original = lane.subprocess.run
    lane.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch) / "tree"
            tree.mkdir()
            return lane.run_battery(tree, None, {_LABEL: [_CONTROL]}, lane.RUST)
    finally:
        lane.subprocess.run = original


def test_a_failed_libtest_record_is_the_red_the_lane_reads():
    ran, results = _run_rust_battery(logfile=f"failed {_CONTROL}\n")
    assert ran and results == {f"{_LABEL}#{_CONTROL}": "FAILED"}


def test_stdout_text_is_not_a_result_even_when_it_looks_like_one():
    """Bazel's merged stream is not the source: a result-looking line there, whatever
    stream it came from, does not satisfy a control the harness never recorded."""
    looking = f"test {_CONTROL} ... FAILED\n"
    for kwargs in ({"stdout": looking}, {"stderr": looking}):
        ran, results = _run_rust_battery(logfile="", **kwargs)
        assert ran and results == {}, kwargs


def test_unrelated_stderr_does_not_count_as_the_control_having_run():
    ran, results = _run_rust_battery(stderr="retained-evidence store: boom\n", logfile="")
    assert ran and results == {}


def test_a_should_panic_control_that_goes_red_is_read_as_red_not_as_never_ran():
    """M325's declared control is a `#[should_panic]` test. Under the weakening libtest writes
    `failed: test did not panic as expected ... <name>`, and that is the red the lane reads."""
    control = "tests::a_key_the_target_does_not_set_is_refused"
    label = "//mcp-re-test-paths:mcp_re_test_paths_test"
    record = f"failed: test did not panic as expected at mcp-re-test-paths/src/lib.rs:69:8 {control}\n"
    def fake_run(argv, **_kwargs):
        path = [a for a in argv if a.startswith("--test_arg=--logfile=")]
        Path(path[0].split("=", 2)[2]).write_text(record)
        return subprocess.CompletedProcess(argv, 0, "", "")

    original = lane.subprocess.run
    lane.subprocess.run = fake_run
    try:
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch) / "tree"
            tree.mkdir()
            ran, results = lane.run_battery(tree, None, {label: [control]}, lane.RUST)
    finally:
        lane.subprocess.run = original
    assert ran and results == {f"{label}#{control}": "FAILED"}


def test_a_different_test_name_does_not_satisfy_the_control():
    ran, results = _run_rust_battery(logfile=f"failed {_CONTROL}_other\n")
    assert f"{_LABEL}#{_CONTROL}" not in results


def test_an_ok_record_does_not_read_as_red():
    ran, results = _run_rust_battery(logfile=f"ok {_CONTROL}\n")
    assert results == {f"{_LABEL}#{_CONTROL}": "ok"}


def test_no_libtest_record_leaves_the_control_unreported():
    ran, results = _run_rust_battery(stdout=f"test {_CONTROL} ... FAILED\n")
    assert ran and results == {}


#: The output of a `bazel test` whose first build attempt lost cache-evicted inputs and
#: whose automatic restart then built the weakened tree and ran the battery.
_EVICTED_THEN_RETRIED = (
    "ERROR: /t/external/rules_rust++crate+crates_mcp_re__redis-1.7.1/BUILD.bazel:15:13: "
    "Compiling Rust rlib redis v1.7.1 (115 files) failed: Lost inputs no longer available "
    "remotely: external/rules_rust++crate+crates_mcp_re__arc-swap-1.9.1/libarc_swap.rlib\n"
    "ERROR: Build did NOT complete successfully\n"
    "Found remote cache eviction error, retrying the build...\n"
    "//mcp-re-proxy:proxy_unit_test                 FAILED in 0.9s\n"
    "Executed 1 out of 1 test: 1 fails locally.\n"
)


def test_a_battery_bazel_rebuilt_after_a_cache_eviction_is_read_as_the_red_it_was():
    """The abandoned attempt's compile-failure lines stay in the output; the command still
    built the weakened tree, ran the control and ended in status 3 with it red."""
    ran, results = _run_rust_battery(
        stderr=_EVICTED_THEN_RETRIED, logfile=f"failed {_CONTROL}\n", returncode=3
    )
    assert ran and results == {f"{_LABEL}#{_CONTROL}": "FAILED"}


def test_a_failed_build_is_not_red_even_beside_a_red_looking_record():
    """Status 1 is a build that did not complete. Whatever a stale record says, nothing ran."""
    ran, results = _run_rust_battery(
        stderr="error[E0425]: cannot find value `base` in this scope\n",
        logfile=f"failed {_CONTROL}\n",
        returncode=1,
    )
    assert not ran and results == {}


def test_an_eviction_bazel_could_not_retry_past_measures_nothing():
    """Retries exhausted is infrastructure: no build completed, so no control was measured,
    and the record keeps Bazel's status and error line so the cause is visible."""
    ran, results = _run_rust_battery(
        stderr=_EVICTED_THEN_RETRIED, logfile=f"failed {_CONTROL}\n", returncode=39
    )
    assert not ran and results == {}
    why = lane._build_failure(_EVICTED_THEN_RETRIED, 39)
    assert why.startswith("exit 39") and "Lost inputs" in why, why


def test_a_stderr_prefix_on_the_stream_line_cannot_hide_a_red_control():
    """The measured M164 defect: unterminated stderr text prefixes the stream's result
    line. The record is the harness's own, so the prefix is not in it."""
    ran, results = _run_rust_battery(
        stdout=f"retained-evidence store: test {_CONTROL} ... FAILED\n",
        logfile=f"failed {_CONTROL}\n",
    )
    assert results == {f"{_LABEL}#{_CONTROL}": "FAILED"}
