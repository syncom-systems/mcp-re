"""The admission commands: `job-started` and `quiesce`."""

from __future__ import annotations

import json
import os

import host_gate
import vm_participant
from arbiter_error import ArbiterError
from job_identity import JobIdentity
import job_liveness
from runner_arbiter_common import (
    EXIT_OK,
    inhibition_file,
    vm_readers,
    vm_workers_or_refuse,
)


def _watched_worker(paths, ident: JobIdentity):
    """The process whose exit ends this job's locks, and the worker record it came from.

    The job's Runner.Worker, found by walking up from this hook. The runner starts the hook
    directly under the worker, so the fallback -- this hook's parent -- is normally the same
    process. If it is not, the holder lets go when that parent exits: the lock drops EARLY,
    which can let two heavy jobs overlap once, and can never leave a lock behind.
    """
    worker = job_liveness.own_worker()
    watch_pid = worker["pid"] if worker else os.getppid()
    if worker is None:
        host_gate.log(paths, "worker.unidentified", key=ident.key, watching=watch_pid)
    return host_gate.Watch(watch_pid, worker)


def _require_participation(paths) -> None:
    """Participation first, BEFORE the host is closed.

    If a runner is not gating itself, draining it proves nothing, and there is no reason to
    close the host to find that out.
    """
    participation = host_gate.verify_participation(vm_readers())
    if participation["all_participating"]:
        return
    missing = [e for e in participation["runners"] if not e["participating"]]
    names = [e["name"] for e in missing]
    # FALLBACK, not the normal mechanism: a participant that cannot gate itself is
    # stopped instead, and only if it is already idle.
    if names == ["dev1-linux"] and vm_participant.available():
        host_gate.log(paths, "participation.fallback", runner="dev1-linux",
                      detail=missing[0]["detail"])
        proof = vm_participant.inhibit_fallback()
        host_gate.write_atomic(inhibition_file(paths), proof)
        return
    # The per-runner detail goes into the log, not only the names. A refusal that says
    # WHICH runner but not WHY costs a diagnosis session, which it did.
    host_gate.log(paths, "participation.refused", runners=participation["runners"])
    detail = "; ".join(f"{e['name']}: {e['detail']}" for e in missing)
    raise ArbiterError(
        f"runner application(s) {names} are not participating in host admission "
        f"({detail}). Refusing to measure: an unhooked runner is unobserved, not quiet."
    )


def cmd_job_started(paths, ident: JobIdentity) -> int:
    # Capacity first, before ANY state is written. A job refused here leaves no active
    # record and holds no reservation, so a full disk cannot also leave the gate dirty --
    # the SLO path below would otherwise reserve the whole host and then refuse, closing
    # every runner behind a job that never ran.
    host_gate.refuse_if_disk_exhausted(paths, ident)

    watch = _watched_worker(paths, ident)

    if not ident.is_slo:
        host_gate.admit_job(paths, ident, watch)
        return EXIT_OK

    # Owner path.
    _require_participation(paths)

    # Reserve, then drain: the holder takes the gate lock (no new job anywhere from here),
    # the file reservation is written for the VM, and the host lock is granted once every
    # admitted macOS job has ended. The VM, which cannot share the locks, drains below.
    holder = host_gate.admit_job(paths, ident, watch)
    try:
        host_gate.await_drain(paths, ident, vm_workers_or_refuse())
    except ArbiterError:
        holder.terminate()
        raise

    # QUIESCENCE IS DELIBERATELY NOT MEASURED HERE.
    #
    # It used to be, and the ordering was wrong. This hook runs before any workflow step,
    # so it precedes the run supervisor's reconciliation of a PREVIOUS run's leftovers --
    # and a stale proxy or Redis fleet contributes real load. Measuring decay before
    # removing them folds their load into the "quiet box" the run claims to have measured
    # on, which is the exact false-quiet this whole mechanism exists to eliminate.
    #
    # The correct order is reserve -> drain -> reconcile -> clean -> QUIESCE, so the lane
    # calls `runner-arbiter quiesce` once the supervisor has proven the plane empty.
    # `assert-exclusive` refuses without an established record, so a lane that skips the
    # step cannot measure anyway.
    host_gate.activate(paths, ident, {"established": None, "deferred_to_lane": True})
    return EXIT_OK


def cmd_quiesce(paths, ident: JobIdentity) -> int:
    """Wait for sustained host quiescence and record the samples that admitted it.

    Called by the lane AFTER the measurement plane has been reconciled and proven clean,
    so the decay being observed is the host settling -- not a previous run still running.
    """
    quiescence = host_gate.await_quiescence()
    host_gate.write_atomic(paths["root"] / f"quiescence-{ident.key}.json", quiescence)
    print(json.dumps(quiescence, indent=2, default=str))
    if not quiescence["established"]:
        raise ArbiterError(
            "host did not become quiescent within the bounded wait; refusing to begin a "
            "release-grade measurement on a busy machine. Report INCONCLUSIVE."
        )
    return EXIT_OK
