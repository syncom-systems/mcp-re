"""CLI for the physical-host admission gate. See `host_gate` for the protocol and why.

Entry points, in the order the host uses them:

    job-started            ACTIONS_RUNNER_HOOK_JOB_STARTED, every runner application
    assert-exclusive       the clause slo.yml evaluates before stage 4
    job-completed          ACTIONS_RUNNER_HOOK_JOB_COMPLETED, every runner application
    local-lease -- CMD     heavy work started by hand: run CMD under the heavy-job locks
    status / dump-env      diagnostics
    recover                operator-only clearing of stale state

Exit codes are the contract with the hooks: a non-zero from `job-started` means the runner
does not execute the job, which is how admission is refused.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from job_identity import JobIdentity  # noqa: E402
from runner_arbiter_admission import cmd_job_started, cmd_quiesce  # noqa: E402
from runner_arbiter_assertion import cmd_assert_exclusive  # noqa: E402
from runner_arbiter_common import (  # noqa: E402
    EXIT_INCONSISTENT,
    EXIT_OK,
    EXIT_REFUSED,
    vm_readers,
    vm_workers_or_refuse,
)
from runner_arbiter_lease import (  # noqa: E402
    LEASE_ENV,
    LEASE_PID_ENV,
    cmd_local_lease,
    describe_holders,
)
from runner_arbiter_operator import (  # noqa: E402
    cmd_dump_env,
    cmd_job_completed,
    cmd_recover,
    cmd_status,
)

__all__ = [
    "EXIT_INCONSISTENT", "EXIT_OK", "EXIT_REFUSED", "LEASE_ENV", "LEASE_PID_ENV",
    "cmd_assert_exclusive", "cmd_job_started", "cmd_local_lease", "cmd_quiesce",
    "cmd_recover", "cmd_status", "describe_holders", "main", "vm_readers",
    "vm_workers_or_refuse",
]

#: Commands that need the paths and the job identity.
_IDENTIFIED = {
    "job-started": cmd_job_started,
    "job-completed": cmd_job_completed,
    "quiesce": cmd_quiesce,
    "assert-exclusive": cmd_assert_exclusive,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runner-arbiter", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--mirror", type=Path, default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, helptext in (
        ("job-started", "ACTIONS_RUNNER_HOOK_JOB_STARTED entry point"),
        ("job-completed", "ACTIONS_RUNNER_HOOK_JOB_COMPLETED entry point"),
        ("quiesce", "wait for sustained quiescence AFTER the plane is proven clean"),
        ("assert-exclusive", "the physical-host exclusivity clause slo.yml evaluates"),
        ("status", "human-readable host state"),
        ("dump-env", "print the hook environment (SLO identification study)"),
    ):
        sub.add_parser(name, help=helptext)
    lease = sub.add_parser("local-lease",
                           help="run a command by hand under the heavy-job locks")
    lease.add_argument("command", nargs=argparse.REMAINDER)
    rec = sub.add_parser("recover", help="operator-only clearing of stale state")
    rec.add_argument("--clear-reservation", action="store_true")
    rec.add_argument("--i-verified-no-owner-job-is-running", action="store_true")
    return parser


def _dispatch(args, paths, ident: JobIdentity) -> int:
    identified = _IDENTIFIED.get(args.cmd)
    if identified is not None:
        return identified(paths, ident)
    if args.cmd == "status":
        return cmd_status(paths)
    if args.cmd == "dump-env":
        return cmd_dump_env(ident)
    if args.cmd == "recover":
        return cmd_recover(paths, args)
    if args.cmd == "local-lease":
        return cmd_local_lease(paths, args.command)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    paths = host_gate.paths(args.root, args.mirror)
    host_gate.ensure_layout(paths)
    ident = JobIdentity.from_env()

    try:
        return _dispatch(args, paths, ident)
    except ArbiterError as exc:
        print(f"runner-arbiter REFUSED: {exc}", file=sys.stderr)
        host_gate.log(paths, "refused", cmd=args.cmd, reason=str(exc))
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
