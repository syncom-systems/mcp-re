"""Controls for the physical-host admission gate.

Everything here runs against temp directories: no test writes /opt, and none needs a runner.
The propositions that CANNOT be established this way -- that two real runner applications on
dev1 honour the gate -- are exercised live and recorded separately; a unit test must not be
allowed to stand in for that.

The cases live in `_host_gate_cases_*.py` beside this file, over the fixtures in
`_host_gate_support.py`; this file runs them in order and reports.

Run:  python3 tools/slo/test_host_gate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config  # noqa: E402
from _host_gate_cases_capacity import (  # noqa: E402
    test_capacity_refusal,
    test_the_hook_consults_the_guard,
)
from _host_gate_cases_leases import test_heavy_slot, test_local_lease  # noqa: E402
from _host_gate_cases_lifecycle import (  # noqa: E402
    test_completion_releases_on_every_path,
    test_crash_leaves_closed_not_open,
    test_drain_refusal_names_the_blocker,
    test_mirror_is_published_for_the_other_kernel,
    test_the_holder_needs_something_to_watch,
    test_the_hook_returns_while_the_holder_lives,
    test_vm_reported_jobs_block_drain,
)
from _host_gate_cases_observation import (  # noqa: E402
    test_listener_freshness_is_timezone_independent,
    test_participation,
    test_quiescence,
    test_stopped_participants_are_quiet,
)
from _host_gate_cases_ordering import (  # noqa: E402
    test_fail_closed,
    test_ordinary_first_then_slo,
    test_reserve_then_drain,
    test_second_slo_cannot_overlap,
    test_simultaneous_admission,
)
from _host_gate_support import (  # noqa: E402
    CI_WORKFLOW,
    CODE_REPO,
    FAILED,
    MCPRE_REPO,
    PASSED,
    SLO_WORKFLOW,
    STARTED_WORKERS,
    check,
    ordinary,
    slo,
    workflow_ref,
)
from job_identity import JobIdentity  # noqa: E402


def test_identification() -> None:
    print("\nSLO identification (§4)")
    check("the SLO workflow path identifies the owner", slo().is_slo)
    check("an ordinary workflow does not", not ordinary().is_slo)

    # The identity is the workflow PATH, not the job title: a title match would admit any
    # workflow that happened to call its job "slo".
    impostor = JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, CI_WORKFLOW),
                           CI_WORKFLOW, "5", "1", "slo")
    check("a job merely NAMED slo is ordinary", not impostor.is_slo)

    # Same workflow path, wrong repository -- another repo cannot reserve this host's SLO.
    foreign = JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, SLO_WORKFLOW),
                          SLO_WORKFLOW, "6", "1", "slo")
    check("the same path in another repository is ordinary", not foreign.is_slo)

    # An empty environment must not accidentally be the owner.
    check("an unidentifiable job is ordinary", not JobIdentity.from_env({}).is_slo)

    parsed = JobIdentity.from_env({
        "GITHUB_REPOSITORY": MCPRE_REPO,
        "GITHUB_WORKFLOW_REF": workflow_ref(MCPRE_REPO, SLO_WORKFLOW),
        "RUNNER_NAME": "dev1-mcp-re", "GITHUB_RUN_ID": "7", "GITHUB_JOB": "slo"})
    check("the real hook env shape parses to the owner", parsed.is_slo,
          f"got path={parsed.workflow_path!r}")


CASES = (
    test_identification, test_reserve_then_drain, test_ordinary_first_then_slo,
    test_second_slo_cannot_overlap, test_simultaneous_admission, test_fail_closed,
    test_completion_releases_on_every_path, test_crash_leaves_closed_not_open,
    test_quiescence, test_participation,
    test_drain_refusal_names_the_blocker,
    test_listener_freshness_is_timezone_independent,
    test_mirror_is_published_for_the_other_kernel,
    test_vm_reported_jobs_block_drain,
    test_capacity_refusal, test_the_hook_consults_the_guard,
    test_heavy_slot, test_stopped_participants_are_quiet,
    test_the_holder_needs_something_to_watch,
    test_the_hook_returns_while_the_holder_lives,
    test_local_lease,
)


def main() -> int:
    print("host-gate controls — temp directories only, no /opt, no runner")
    # The heavy slot serializes dev1 jobs; the older tests admit several at once, so they run
    # with it off, and test_heavy_slot switches it on for itself.
    host_gate_config.HEAVY_RUNNERS = frozenset()
    for fn in CASES:
        fn()
    for worker in STARTED_WORKERS:
        if worker.poll() is None:
            worker.kill()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
