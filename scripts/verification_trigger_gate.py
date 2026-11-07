#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verification-trigger gate — what starts exhaustive verification, and what cannot.

THE CONTRACT. Four workflows own the scheduling of assurance, and each has one job:

  pre-merge.yml      every pull request, no path filter. Bounded: structural gates, the Bazel
                     build and test, lint, SDK suites.
  post-merge.yml     every push to main: the same jobs again, on the merged result.
  mutation-probe.yml a pull request that moves a unit it can probe, bounded by a unit cap and a
                     timeout; anything it cannot bound is DEFERRED, never widened.
  verification.yml   the COMPLETE run. Only the weekly schedule and an explicit dispatch start
                     it. No `pull_request`, no `push`, no `paths:` filter.

A change may invalidate every piece of formal evidence — a toolchain bump moves all 314 unit
fingerprints — without authorizing the remeasurement. Invalidation is a fact the fingerprint
and `verify --gate` report (evidence STALE or MISSING, never verified); remeasuring is a
decision a person or a schedule takes. This gate holds the first apart from the second.

WHAT IT PROVES, from the workflows as written:

  1. `verification.yml`'s triggers are exactly `schedule` and `workflow_dispatch`, with no
     path filter, and no step of it scopes by `select-units` or falls back to a full run.
     Its first job refuses any other event, so a trigger added by mistake fails instead of
     measuring.
  2. No other workflow calls it (`uses:`), follows it (`workflow_run`) or dispatches it.
  3. `pre-merge.yml` starts on every pull request and is callable; `post-merge.yml` starts on
     push to main and calls it.
  4. `mutation-probe.yml` starts on no push, has a pull-request path filter, a job timeout of
     at most 30 minutes, a `--max-units` cap of at most 20, defers when `select-units` fails
     (a deferral SKIPS the `probe` job, so one that applied nothing never reads as measured),
     and installs no toolchain of its own.
  5. Negative controls, run against the real workflow files: a pull request or push that
     changes `MODULE.bazel`, a lockfile, the toolchain pin, the verification platform or the
     workflow itself starts no complete run, and the verification-platform paths that DO
     start the bounded probe are deferred by `select-units`.
  6. A wildcard-free path filter names something the tree holds or a lane reads.

WHAT IT DOES NOT PROVE: that any run passes, or that a lane measures what it claims. The
`aggregate` job must still run `verify --aggregate --gate`, which reports a missing record as
INCOMPLETE; this gate checks only that it does.

Run:  python3 scripts/verification_trigger_gate.py
      python3 scripts/verification_trigger_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _verification_trigger.config import (  # noqa: E402,F401
    COMPLETE_EVENTS,
    CONTROL_PATHS,
    PLATFORM_PATHS,
    PROBE_EVENTS,
    PROBE_MAX_TIMEOUT_MINUTES,
    PROBE_MAX_UNITS,
    REPO,
    WORKFLOWS,
)
from _verification_trigger.cli import judge  # noqa: E402
from _verification_trigger.complete_run import check_complete_run  # noqa: E402,F401
from _verification_trigger.gate import all_failures, fingerprint_inputs, read_texts  # noqa: E402,F401
from _verification_trigger.paths import (  # noqa: E402,F401
    check_controls,
    check_indirect,
    check_merge_path,
    stale_filters,
)
from _verification_trigger.probe import check_bounded_probe  # noqa: E402,F401
from _verification_trigger.reading import job_uses, parse, parse_yaml, starts_on  # noqa: E402,F401
from _verification_trigger.selftest import selftest  # noqa: E402,F401


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
