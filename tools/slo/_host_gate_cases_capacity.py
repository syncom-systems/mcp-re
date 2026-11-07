"""Controls for capacity admission: the disk guard, and that the hook entry point asks it."""

from __future__ import annotations

import os
from contextlib import contextmanager

import host_gate
import host_gate_capacity
import host_locks
import runner_arbiter
from _host_gate_support import (
    all_free,
    check,
    environment,
    fresh,
    locks,
    ordinary,
    recovery,
    within,
)
from arbiter_error import ArbiterError

#: Everything below fixes the SAME simulated free space and varies only the identity or the
#: threshold. A test that let free space float would prove nothing: above the floor every
#: job is admitted, so an "admitted" assertion holds with the guard deleted.
STARVED_GB = 3.0   # far under the 25 GB floor
ROOMY_GB = 400.0


def _guard_refusal(paths, ident, measure):
    """The guard's refusal message, or None if the job is admitted."""
    try:
        host_gate.refuse_if_disk_exhausted(paths, ident, measure=measure)
    except ArbiterError as exc:
        return str(exc)
    return None


def _unreadable(_volume):
    raise OSError("simulated statvfs failure")


def _guard_decisions(paths, tmp) -> None:
    starved = lambda _volume: STARVED_GB  # noqa: E731
    roomy = lambda _volume: ROOMY_GB      # noqa: E731

    message = _guard_refusal(paths, ordinary(1), starved)
    check("an ordinary job is refused below the floor", message is not None)

    # The positive control. Without it the refusal above also passes against a guard that
    # refuses everything, which would be a total outage rather than a guard.
    check("the same job is admitted above the floor",
          _guard_refusal(paths, ordinary(2), roomy) is None)

    # THE DISCRIMINATING PAIR, both at 3 GB. The recovery lane is the cure for the
    # condition being refused; a guard that refused it would deadlock the host. Note this
    # is asserted at the SAME free space as the refusal above -- asserting it at 400 GB
    # would hold with the exemption deleted.
    check("the retention lane is admitted below the floor",
          _guard_refusal(paths, recovery(), starved) is None)

    # ...and it is the WORKFLOW that is exempt, not the repository. matssun/code runs CI
    # here too, and exempting the whole repository would exempt nearly everything.
    check("another workflow in the same repository is still refused",
          _guard_refusal(paths, ordinary(3), starved) is not None)

    # The refusal is read by an operator who has no context, so it must name the volume it
    # measured: the host and the colima VM measure DIFFERENT filesystems through this same
    # code, and a number without its volume cannot be checked.
    text = message or ""
    check("the refusal names the volume and both numbers",
          str(tmp) in text and "3.0" in text and "25" in text,
          detail=text if message is not None else "no refusal")

    # Fail-open, deliberately and against the rest of this file's direction: an unreadable
    # volume must not stop all work on the host.
    check("an unmeasurable volume admits rather than refuses",
          _guard_refusal(paths, ordinary(4), _unreadable) is None)


def test_capacity_refusal() -> None:
    print("\ncapacity admission")
    p = fresh()
    tmp = p["root"]

    with environment(RUNNER_TEMP=str(tmp)):
        _guard_decisions(p, tmp)

    # A hook environment naming no work path at all cannot be measured either, and must not
    # refuse. Asserted with the work-path variables absent rather than by faking a failure.
    for var in ("RUNNER_WORKSPACE", "GITHUB_WORKSPACE", "RUNNER_TEMP"):
        os.environ.pop(var, None)
    check("a job whose work path is unknown is not refused",
          _guard_refusal(p, ordinary(5), lambda _volume: STARVED_GB) is None)


@contextmanager
def _host_with_space(paths, free_gb: float):
    """A hook environment naming `paths`' root as the work volume, with `free_gb` free."""
    real_free_gb = host_gate_capacity.free_gb
    host_gate_capacity.free_gb = lambda _volume: free_gb
    try:
        with environment(RUNNER_TEMP=str(paths["root"])):
            yield
    finally:
        host_gate_capacity.free_gb = real_free_gb


def _hook_outcome(paths, ident):
    """`(return code, None)` if `job-started` admits, `(None, message)` if it refuses."""
    try:
        return runner_arbiter.cmd_job_started(paths, ident), None
    except ArbiterError as exc:
        return None, str(exc)


def _admission_through_the_hook(paths) -> None:
    rc, error = _hook_outcome(paths, ordinary(11))
    if error is not None:
        check("a host with room admits through the hook entry point", False, error)
        return
    check("a host with room admits through the hook entry point", rc == 0)
    check("and the admitted job DID get a lock holder",
          [h["key"] for h in host_locks.holders(paths["root"])] == [ordinary(11).key])
    host_gate.job_completed(paths, ordinary(11))
    check("and its completion frees the host lock",
          within(lambda: locks(paths)["host"] == "free") is not None)


def test_the_hook_consults_the_guard() -> None:
    """That `job-started` ASKS. The predicate being correct is not enough.

    The checks above prove `refuse_if_disk_exhausted` decides correctly. They say NOTHING
    about whether the admission path calls it -- delete that one line from
    `cmd_job_started` and every one of them stays green while a full host admits work
    exactly as it did during the fortnight outage. This is the same gap a poison pill found
    in the retention collector, arriving at a different seam.
    """
    print("\nthe hook consults the guard")

    p = fresh()
    with _host_with_space(p, STARVED_GB):
        rc, message = _hook_outcome(p, ordinary(10))
    check("a starved host refuses through the hook entry point", message is not None,
          detail=f"returned {rc} instead of raising")

    # Refused BEFORE any state is written. A job that left an active record behind would
    # leak one per refused job, and on the SLO path would reserve the whole host and then
    # refuse -- closing every runner behind a job that never ran.
    check("a refused job leaves no lock holder", not host_locks.holders(p["root"]))
    check("and holds no lock", all_free(p))
    check("a refused job leaves the gate open",
          host_gate.read_gate(p).get("state", host_gate.OPEN) == host_gate.OPEN)

    # The positive control: the same entry point admits when there is room. Without it the
    # refusal above would pass against a `cmd_job_started` that raised unconditionally.
    p2 = fresh()
    with _host_with_space(p2, ROOMY_GB):
        _admission_through_the_hook(p2)
