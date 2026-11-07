#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-MCPRE-051 §7 local-regression SLO gate.

Compares a FRESH load-harness report (the JSON the harness writes to
MCP_RE_LOADGEN_OUT) against the committed provisional baseline
(docs/bench/adr-051-baseline-local.json) under the ACTIVE local_regression
tolerances declared in docs/bench/adr-051-slo-targets.json.

This is the executable half of MCPRE-110's committable deliverable. It is a
LOCAL-REGRESSION gate, not a production-SLO gate: it asserts a change has not
regressed the serving path against its own recorded baseline. The absolute
production SLOs (and the authoritative 1->N scaling acceptance) live in the
`production_slo` block of the targets file and stay null until a dedicated
load-generator run on the production hardware class exists (GKE fleet run).

The replay-race and bounded-drain gates are ABSOLUTE and hardware-independent;
they are enforced by their own always-on tests
(//mcp-re-proxy:replay_race_harness_test, //mcp-re-proxy:async_drain_test) and
are NOT re-checked here — this script only guards the throughput/latency
regression band.

Usage — prefer the lane script, which does both steps and refuses the known traps:

    scripts/local_slo_lane.sh          # 6 anchor reps, each gated by THIS script

By hand (see docs/dev/local-gate-order.md before you do):

    # 1. produce a fresh report at the baseline anchor config. `--exact`, NEVER
    #    `--ignored`: this bench is not an #[ignore] test (the target is built with the
    #    redis_replay feature), so `--ignored` selects ZERO tests, exits 0 and writes no
    #    report. MCP_RE_LOADGEN_OUT must be ABSOLUTE — `bazel run` starts the test binary
    #    in its runfiles tree. The harness spawns the real CLI, which the target depends on,
    #    so it is built with the same features as the test.
    bazel build -c opt //mcp-re-proxy:tls_load_harness_bench
    MCP_RE_LOADGEN_CORES=1 MCP_RE_LOADGEN_CONCURRENCY=128 \\
    MCP_RE_LOADGEN_REQUESTS=8000 MCP_RE_LOADGEN_MODE=cold \\
    MCP_RE_LOADGEN_HW_CLASS=... MCP_RE_LOADGEN_OUT=$PWD/fresh.json \\
    bazel run -c opt //mcp-re-proxy:tls_load_harness_bench -- \\
        tls_load_harness_bench --exact --nocapture

    # 2. gate it
    python3 scripts/adr051_slo_gate.py --report $PWD/fresh.json

Measure on a QUIET box: the loadgen is co-located with the proxy, so an unrelated
build on the same machine produces an environmental FAIL that says nothing about the
code (this cost one full A/B/B/A investigation in 2026-07). The lane script enforces
this; a hand-run does not.

ONE ANCHOR PER HARDWARE CLASS, and this gate refuses to compare across them. It used to
compare whatever report it was handed against the single committed baseline, whatever
`config.hardware_class` that report carried — so a run measured somewhere else was
adjudicated against numbers recorded on a developer workstation and the verdict read as a
code result. A cross-class comparison is not a stricter or a looser gate; it is a gate
about a different question, which is the whole point of the measurement context in
`config/performance-surface.toml`. The anchor for a report is therefore resolved FROM the
report's own class, and a class with no declared anchor yields UNANCHORED rather than a
pass or a regression: nothing has been measured for that class to be compared against yet.

Exit status: 0 = within tolerance, 1 = regression, 2 = usage/data error,
             4 = not comparable (no anchor for this report's hardware class).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _adr051_slo.anchor import load_json, resolve_anchor, unanchored  # noqa: E402,F401
from _adr051_slo.cli import run  # noqa: E402
from _adr051_slo.config import DEFAULT_TARGETS, NOT_COMPARABLE, REPO_ROOT  # noqa: E402,F401
from _adr051_slo.regression import evaluate, print_checks  # noqa: E402,F401
from _adr051_slo.selftest import selftest  # noqa: E402


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return run()


if __name__ == "__main__":
    sys.exit(main())
