"""The SLO owner's reservation record and the file gate's repair.

The kernel lock is the authority; the gate FILE mirrors it for the VM and the SLO lane. Each
transition here is made under `mutex` and committed with `commit`.
"""

from __future__ import annotations

import os
import socket
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
import host_locks  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from host_gate_state import active_records, commit, log, mutex, now, read_gate  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

_HELD = (cfg.RESERVING, cfg.RESERVED)


def repair_stale_gate(p: dict[str, Path]) -> bool:
    """Bring the gate FILE back in line with the gate LOCK. True if it was stale.

    The file is a mirror for the VM and for the SLO lane's own checks; the authority is the
    kernel lock the owner's holder takes. A file that says RESERVING/RESERVED while nobody
    holds the gate lock exclusively describes an owner that is gone -- its holder was killed
    before it could write RELEASED -- so it is committed RELEASED. The file is only ever
    written RESERVING after the holder reports the gate lock held (see `admit_job`), so this
    cannot race a reservation being made.
    """
    with mutex(p):
        try:
            gate = read_gate(p)
        except ArbiterError:
            return False
        if gate.get("state") not in _HELD:
            return False
        if not host_locks.would_grant(p["root"], "gate", host_locks.SH):
            return False  # somebody holds it exclusively: the reservation is live
        commit(p, {**gate, "state": cfg.RELEASED, "released_at": now(),
                   "released_by": "repair: no process holds the gate lock"})
    log(p, "gate.repaired", reservation_id=gate.get("reservation_id"),
        owner=gate.get("owner", {}).get("key"))
    return True


def release_owner(p: dict[str, Path], key: str, why: str) -> bool:
    """Commit RELEASED if `key` owns the file gate. Called by the owner's holder on exit."""
    with mutex(p):
        try:
            gate = read_gate(p)
        except ArbiterError:
            return False
        if gate.get("owner", {}).get("key") != key or gate.get("state") not in _HELD:
            return False
        commit(p, {**gate, "state": cfg.RELEASED, "released_at": now(), "released_by": why})
    log(p, "gate.released", key=key, why=why)
    return True


def job_completed(p: dict[str, Path], ident: JobIdentity) -> dict:
    """Release whatever this job held: success, failure and cancellation alike.

    The holder would release the locks by itself when the worker exits a moment later; this
    only makes it immediate. A job admitted before the kernel locks existed has a legacy
    ACTIVE record and no holder; both cases are handled.
    """
    holder = host_locks.signal_holder(p["root"], ident.key)
    removed_active = False
    released = False
    with mutex(p):
        try:
            (p["active"] / f"{ident.key}.json").unlink()
            removed_active = True
        except FileNotFoundError:
            pass
        try:
            gate = read_gate(p)
        except ArbiterError:
            gate = {}
        if gate.get("owner", {}).get("key") == ident.key and gate.get("state") in _HELD:
            commit(p, {**gate, "state": cfg.RELEASED, "released_at": now()})
            released = True
    log(p, "job.completed", key=ident.key, holder_signalled=holder,
        removed_active=removed_active, released_reservation=released)
    return {"holder": holder, "removed_active": removed_active,
            "released_reservation": released}


def _new_reservation(ident: JobIdentity) -> dict:
    return {
        "schema": cfg.SCHEMA,
        "state": cfg.RESERVING,
        "reservation_id": str(uuid.uuid4()),
        "owner": {"key": ident.key, **asdict(ident)},
        "host": socket.gethostname(),
        "created_at": now(),
        "activated_at": None,
        "released_at": None,
        "pid": os.getpid(),
        "stale_recovery": {
            "policy": "follows the gate lock",
            "note": "This file mirrors the gate lock held by the owner's lock holder. "
                    "The holder writes RELEASED when it exits; if it is killed first, "
                    "the next admission or status finds nobody holding the gate lock "
                    "and commits RELEASED. No TTL is involved.",
        },
    }


def _overlap_refusal(gate: dict) -> ArbiterError:
    owner = gate.get("owner", {})
    return ArbiterError(
        f"host already reserved ({gate.get('reservation_id')}) by run "
        f"{owner.get('run_id')} on {owner.get('runner')}; two SLO measurements "
        "may not overlap."
    )


def grant_reservation(p: dict[str, Path], ident: JobIdentity) -> dict:
    """Record OPEN -> RESERVING(owner) in the file gate, for the VM and the SLO lane.

    Called by `admit_job` once the owner's holder holds the gate lock exclusively, which is
    what actually stops admission on every macOS runner.
    """
    with mutex(p):
        gate = read_gate(p)
        if gate.get("state", cfg.OPEN) in _HELD:
            if gate.get("owner", {}).get("key") != ident.key:
                raise _overlap_refusal(gate)
            return gate
        granted = _new_reservation(ident)
        commit(p, granted)
        log(p, "gate.reserved", reservation_id=granted["reservation_id"], owner=ident.key)
        return granted


def _vm_reported_others(p: dict[str, Path], ident: JobIdentity) -> list[dict]:
    return [r for r in active_records(p)
            if r.get("key") != ident.key and r.get("reported_by") == "vm"]


def _waiting_on(others: list[dict]) -> list[dict]:
    return [{"key": r.get("key"),
             "runner": r.get("identity", {}).get("runner"),
             "job": r.get("identity", {}).get("job"),
             "reported_by": r.get("reported_by")} for r in others]


def _drain_refusal(wait_s: int, waiting_on: list[dict], vm_n: int) -> ArbiterError:
    # Name the blocker. A refusal that says only "did not drain" sends the operator
    # to the arbiter log to discover WHICH job held the host.
    blockers = ", ".join(f"{w['runner']}:{w['job']}" for w in waiting_on) or f"{vm_n} VM worker(s)"
    return ArbiterError(
        f"pre-existing work did not drain within {wait_s}s and the host reservation "
        f"is being released so ordinary work can resume. Still running: {blockers} "
        f"(VM-reported active={len(waiting_on)}, vm workers={vm_n}). The benchmark was "
        f"NOT measured beside it, and that work was NOT killed — re-dispatch the SLO "
        f"when the host is quieter."
    )


def _announce_due(elapsed: float, last_announce: float) -> bool:
    return last_announce == 0.0 or elapsed - last_announce >= cfg.DRAIN_ANNOUNCE_S


def await_drain(p: dict[str, Path], ident: JobIdentity, vm_workers,
                wait_s: int = cfg.DRAIN_WAIT_S) -> list[dict]:
    """Wait for the VM to drain. The macOS drain is the host lock, already held by now.

    `vm_workers` returns the VM's live worker count, injected so this stays testable
    without a VM. VM-reported ACTIVE records count too.
    """
    started = time.monotonic()
    deadline = started + wait_s
    announced: list[dict] = []
    last_announce = 0.0
    while True:
        others = _vm_reported_others(p, ident)
        vm_n = vm_workers()
        if not others and vm_n == 0:
            log(p, "gate.drained", drained=announced)
            return announced

        waiting_on = _waiting_on(others)
        announced = announced or waiting_on
        if time.monotonic() >= deadline:
            raise _drain_refusal(wait_s, waiting_on, vm_n)

        elapsed = time.monotonic() - started
        if _announce_due(elapsed, last_announce):
            log(p, "gate.draining", waited_s=int(elapsed), budget_s=wait_s,
                waiting_on=waiting_on, vm_workers=vm_n)
            last_announce = elapsed
        time.sleep(cfg.POLL_S)


def activate(p: dict[str, Path], ident: JobIdentity, quiescence: dict) -> dict:
    """RESERVING -> RESERVED. The owner may now measure."""
    with mutex(p):
        gate = read_gate(p)
        if gate.get("owner", {}).get("key") != ident.key:
            raise ArbiterError("cannot activate a reservation this job does not own")
        activated = {**gate, "state": cfg.RESERVED, "activated_at": now(),
                     "quiescence": {"established": quiescence.get("established"),
                                    "duration_s": quiescence.get("duration_s")}}
        commit(p, activated)
        log(p, "gate.activated", reservation_id=activated.get("reservation_id"))
        return activated
