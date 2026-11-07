"""The SLO run lifecycle authority: one owner for every ephemeral measurement resource.

WHY IT IS NOT THE HOST ARBITER, AND NOT THE HARNESS
===================================================

Two separate authorities, both necessary:

    host arbiter  (host_gate)      answers "is another RUNNER working on this machine?"
    run supervisor (this)          answers "is anything left over from a previous SLO RUN,
                                   and did this run remove everything it created?"

Host exclusivity says nothing about a Redis fleet or a proxy child surviving a crashed run.
Their load is real, it lands in the quiescence window, and a fleet answering on a port the
new run expects to own would be measured as though this run had started it.

And it is not the harness, because the harness is INSIDE cargo. `RedisFleet`'s `Drop` guard
is a genuine fast path -- milliseconds on a normal exit and on a panic -- but it is the
frame that disappears when the job is cancelled or the process is killed. A cleanup
authority must survive the thing it cleans up after, so it runs one level out.

THE ORDERING, AND WHY RECONCILE COMES BEFORE QUIESCE
====================================================

    reserve host ─▶ drain runners        (host_gate, already done when we are called)
    reconcile previous runs' leftovers
    assert clean start                   exact baseline, or refuse
    quiesce                              ONLY now does the clock start
    create run id ─▶ start resources ─▶ await readiness
    measure
    teardown                             ALWAYS, including failure and cancellation
    assert clean end                     or the result is not attestable
    persist ─▶ release host

Measuring load decay while a stale proxy is still running folds that load into the "quiet
box" the run claims to have measured on. Reconciliation must therefore precede quiescence,
not follow it.

OWNERSHIP, AND WHAT WE REFUSE TO TOUCH
======================================

Every Docker resource a run creates carries `com.mcp-re.slo=true` and
`com.mcp-re.slo.run=<RUN_ID>`. Reconciliation acts ONLY on resources whose ownership is
established that way. An unlabelled container holding a port we need is somebody else's
process; that is INFRASTRUCTURE_UNAVAILABLE and no benchmark runs. We never `pkill mcp-re`,
never remove by name pattern, never "kill whatever owns port X".

Resources left by a SIGKILL or a power loss are not cleaned by this run's teardown -- no
code of ours executed. They are repaired by the NEXT run's reconciliation, which is exactly
why ownership has to be a durable label rather than a live object's destructor.

TEARDOWN IS PART OF THE VERDICT
===============================

A measurement that passes every performance criterion and leaves a container running has
violated its environmental contract. Its number was taken on a plane we can no longer
characterise, and reusing it would propagate that. So `assert_clean_end` is a gate:

    performance ∧ clean-start ∧ exclusivity ∧ quiescence ∧ teardown  =  attestable
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_supervisor_reconcile import assert_clean_start, reconcile_previous  # noqa: E402
from run_supervisor_record import (  # noqa: E402
    RUNS_ROOT,
    SCHEMA,
    LifecycleError,
    manifest_path,
    run_id_from_environment,
    write_manifest,
)
from run_supervisor_resources import (  # noqa: E402
    GRACE_S,
    OWNER_LABEL,
    RUN_LABEL,
    VERIFY_S,
    docker,
    endpoint,
    owned_resources,
    unowned_outside_baseline,
)
from run_supervisor_teardown import assert_clean_end, teardown  # noqa: E402

__all__ = [
    "GRACE_S", "OWNER_LABEL", "RUNS_ROOT", "RUN_LABEL", "SCHEMA", "VERIFY_S",
    "LifecycleError", "assert_clean_end", "assert_clean_start", "docker", "endpoint",
    "main", "manifest_path", "owned_resources", "reconcile_previous",
    "run_id_from_environment", "teardown", "unowned_outside_baseline", "write_manifest",
]

EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE = 0, 1, 2


def _begin(run: str) -> int:
    reconciled = reconcile_previous(run)
    clean = assert_clean_start(run)
    write_manifest(run, phase="begin", reconciled=reconciled, clean_start=clean)
    print(json.dumps({"run_id": run, "reconciled": reconciled,
                      "clean_start": clean}, indent=2, default=str))
    if not reconciled["reconciled"]:
        raise LifecycleError(
            f"previous runs' resources survived reconciliation: {reconciled['survivors']}")
    if not clean["at_baseline"]:
        unavailable = any("INFRASTRUCTURE_UNAVAILABLE" in p for p in clean["problems"])
        prefix = "INFRASTRUCTURE_UNAVAILABLE: " if unavailable else ""
        raise LifecycleError(prefix + "; ".join(clean["problems"]))
    return EXIT_OK


def _end(run: str) -> int:
    torn = teardown(run)
    clean = assert_clean_end(run)
    write_manifest(run, phase="end", teardown=torn, clean_end=clean)
    print(json.dumps({"run_id": run, "teardown": torn, "clean_end": clean},
                     indent=2, default=str))
    if not clean["clean"]:
        raise LifecycleError(
            f"SLO RESULT: INFRASTRUCTURE_FAILURE — resources created by {run} "
            f"survived teardown: {clean['remaining']}. The measurement is NOT "
            f"attestable: cleanup success is part of the validity of the result.")
    return EXIT_OK


def _status(run: str) -> int:
    print(json.dumps({
        "run_id": run, "endpoint": endpoint(),
        "owned_all_runs": owned_resources(),
        "owned_this_run": owned_resources(run),
        "unowned": unowned_outside_baseline(),
    }, indent=2, default=str))
    return EXIT_OK


def _run_id(run: str) -> int:
    print(run)
    return EXIT_OK


#: The lane drives these in order.
COMMANDS = {"run-id": _run_id, "begin": _begin, "end": _end, "status": _status}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slo-run-supervisor", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run-id", help="print the run identity for this execution")
    sub.add_parser("begin", help="reconcile previous runs, then assert the clean baseline")
    sub.add_parser("end", help="tear down this run and assert the plane is clean again")
    sub.add_parser("status", help="what is on the plane, and who owns it")
    args = parser.parse_args(argv)

    run = os.environ.get("MCP_RE_SLO_RUN_ID") or run_id_from_environment()

    try:
        return COMMANDS[args.cmd](run)
    except LifecycleError as exc:
        print(f"slo-run-supervisor REFUSED: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE if "INFRASTRUCTURE_UNAVAILABLE" in str(exc) else EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
