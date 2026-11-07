# SPDX-License-Identifier: Apache-2.0
"""The false-ready catalogue: every shape that must NOT read as READY."""

from __future__ import annotations

from _merge_readiness import selftest_registry, selftest_verdict, selftest_workflows
from _merge_readiness.tally import Tally


def selftest() -> int:
    tally = Tally()
    selftest_verdict.run(tally)
    selftest_workflows.run(tally)
    selftest_registry.run(tally)
    print(f"merge_readiness_gate selftest: {'PASS' if tally.bad == 0 else f'FAIL ({tally.bad})'}")
    return 1 if tally.bad else 0
