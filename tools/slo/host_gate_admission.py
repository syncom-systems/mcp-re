"""Admission under the kernel locks: a per-job holder takes them and keeps them.

Both entry points spawn a holder (see `host_locks`), wait for its answer within bounds, and
refuse by raising `ArbiterError`. The holder keeps the locks until the watched process exits.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
import host_locks  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from host_gate_reservation import grant_reservation, release_owner, repair_stale_gate  # noqa: E402
from host_gate_state import log  # noqa: E402
from job_identity import JobIdentity  # noqa: E402


@dataclass(frozen=True)
class Watch:
    """The process whose exit ends a job's locks, and what is known about it."""

    pid: int
    worker: dict | None = None


@dataclass(frozen=True)
class Lease:
    """A command run by hand: the holder key, the lease process, and the record kept."""

    key: str
    watch_pid: int
    record: dict


def lock_bounds() -> dict:
    return {"gate_wait": cfg.ORDINARY_WAIT_S, "heavy_wait": cfg.HEAVY_WAIT_S,
            "drain_wait": cfg.DRAIN_WAIT_S}


def local_lease_key(pid: int | None = None) -> str:
    """A holder key for a command run by hand on this host, unique per lease process.

    `JobIdentity.from_env()` outside a runner yields the same key for every caller, so two
    concurrent leases would share one holder record; the pid makes each its own.
    """
    user = os.environ.get("USER") or "user"
    raw = f"local-{user}-{pid or os.getpid()}"
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in raw)


def _answer_budget_s(plan: str, bounds: dict) -> int:
    waits = sum(int(bounds[step[3]]) for step in host_locks.PLANS[plan] if step[0] == "take")
    return waits + 60


def _await_holder(proc, r: int, budget_s: int, **hooks) -> str:
    try:
        return host_locks.await_answer(proc, r, budget_s, **hooks)
    except BaseException:
        proc.terminate()
        raise


def admit_job(p: dict[str, Path], ident: JobIdentity, watch: Watch,
              bounds: dict | None = None):
    """Admit this job under the kernel locks, or refuse. Returns the holder process.

    The holder takes this job's locks (see `host_locks`) and keeps them until `watch.pid`
    -- the job's Runner.Worker -- exits. For the SLO owner the file reservation is written
    once the holder reports the gate lock held, before the drain, so the VM (which reads
    the file mirror) stops admitting from that moment too.
    """
    repair_stale_gate(p)
    plan = host_locks.plan_for(ident.is_slo, ident.runner, cfg.HEAVY_RUNNERS)
    b = {**lock_bounds(), **(bounds or {})}
    proc, r = host_locks.spawn_holder(p["root"], p["mirror"], ident.key, plan, watch.pid, b,
                                      {"identity": asdict(ident), "worker": watch.worker})
    on_gate = (lambda: grant_reservation(p, ident)) if ident.is_slo else None
    answer = _await_holder(proc, r, _answer_budget_s(plan, b), on_gate=on_gate)
    if answer != "ADMITTED":
        if ident.is_slo:
            release_owner(p, ident.key, "the owner was refused admission")
        log(p, "admission.refused", key=ident.key, plan=plan, answer=answer)
        raise ArbiterError(answer)
    log(p, "admission.admitted", key=ident.key, plan=plan, holder=proc.pid, watch=watch.pid)
    return proc


def admit_local(p: dict[str, Path], lease: Lease, bounds: dict | None = None, on_wait=None):
    """Take the HEAVY lock set for a command started by hand, not by a runner.

    The same plan a dev1 CI job takes -- heavy EX -> gate SH -> host SH -- under the same
    holder, so a local run and a CI job exclude each other exactly as two CI jobs do, and
    an SLO reservation drains it like any other admitted job. `lease.watch_pid` is the lease
    process: when it exits, by any cause, the holder exits and the kernel frees the locks.
    Returns the holder process; raises ArbiterError when refused.
    """
    repair_stale_gate(p)
    b = {**lock_bounds(), **(bounds or {})}
    proc, r = host_locks.spawn_holder(p["root"], p["mirror"], lease.key, "heavy",
                                      lease.watch_pid, b, lease.record)
    answer = _await_holder(proc, r, _answer_budget_s("heavy", b), on_idle=on_wait,
                           poll_s=cfg.LEASE_POLL_S)
    if answer != "ADMITTED":
        log(p, "lease.refused", key=lease.key, answer=answer)
        raise ArbiterError(answer)
    log(p, "lease.admitted", key=lease.key, holder=proc.pid, watch=lease.watch_pid)
    return proc
