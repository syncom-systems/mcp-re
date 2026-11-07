"""`assert-exclusive`: every clause the closing claim rests on, evaluated and recorded."""

from __future__ import annotations

import json
import socket

import host_gate
import host_locks
import vm_participant
from arbiter_error import ArbiterError
from job_identity import JobIdentity
from runner_arbiter_common import (
    EXIT_INCONSISTENT,
    EXIT_OK,
    inhibition_file,
    vm_readers,
)


def _reservation_problems(gate: dict, ident: JobIdentity) -> list[str]:
    problems: list[str] = []
    if gate.get("state") != host_gate.RESERVED:
        problems.append(f"gate state is {gate.get('state')}, not {host_gate.RESERVED}")
    if gate.get("owner", {}).get("key") != ident.key:
        problems.append("this run does not own the reservation")
    return problems


def _lock_problems(paths, ident: JobIdentity, locks: dict) -> list[str]:
    """The kernel's own answer: this run's holder must hold the gate and host locks
    exclusively. If either can be taken shared, the reservation is not in force."""
    problems = [f"the {name} lock is {locks[name]}, not held exclusively"
                for name in ("gate", "host") if locks[name] != "exclusive"]
    own_holder = [h for h in host_locks.holders(paths["root"]) if h.get("key") == ident.key]
    if not own_holder:
        problems.append("this run has no lock holder record")
    return problems


def _participation_problems(participation: dict, inhibited: bool) -> list[str]:
    if participation["all_participating"] or inhibited:
        return []
    names = [e["name"] for e in participation["runners"] if not e["participating"]]
    return [f"runner application(s) not participating: {names}"]


def _vm_observation(problems: list[str]):
    """The VM's Runner.Worker count, observed directly.

    The claim is about the PHYSICAL host, so the VM must be observed directly. A macOS
    pgrep can never stand as proof here -- it cannot see the VM's kernel at all.
    """
    try:
        if vm_participant.available():
            count = vm_participant.worker_count()
            if count:
                problems.append(f"{count} Runner.Worker process(es) live in the VM")
            return count
        if vm_participant.stopped():
            return 0
        problems.append("the VM could not be observed")
    except ArbiterError as exc:
        problems.append(str(exc))
    return None


def _quiescence_record(paths, ident: JobIdentity, problems: list[str]):
    qpath = paths["root"] / f"quiescence-{ident.key}.json"
    quiescence = json.loads(qpath.read_text()) if qpath.exists() else None
    if not quiescence or not quiescence.get("established"):
        problems.append("quiescence was not established for this reservation")
    return quiescence


def cmd_assert_exclusive(paths, ident: JobIdentity) -> int:
    """Every clause the closing claim rests on, evaluated and recorded together."""
    gate = host_gate.read_gate(paths)
    problems = _reservation_problems(gate, ident)

    others = [r for r in host_gate.active_records(paths) if r.get("key") != ident.key]
    if others:
        problems.append(f"{len(others)} non-owner ACTIVE record(s) remain")

    locks = host_locks.lock_state(paths["root"])
    problems += _lock_problems(paths, ident, locks)

    participation = host_gate.verify_participation(vm_readers())
    inhibited = inhibition_file(paths).exists()
    problems += _participation_problems(participation, inhibited)

    macos = host_gate.macos_workers()
    if len(macos) > 1:
        problems.append(f"{len(macos)} macOS Runner.Worker processes observed")

    vm_workers = _vm_observation(problems)
    quiescence = _quiescence_record(paths, ident, problems)

    verdict = {
        "schema": host_gate.SCHEMA,
        "assertion": "physical-host-exclusive",
        "host": socket.gethostname(),
        "at": host_gate.now(),
        "reservation_id": gate.get("reservation_id"),
        "gate_state": gate.get("state"),
        "reserved_at": gate.get("created_at"),
        "activated_at": gate.get("activated_at"),
        "owner_run_id": gate.get("owner", {}).get("run_id"),
        "non_owner_active": len(others),
        "locks": locks,
        "participation": participation,
        "vm_inhibition_fallback_applied": inhibited,
        "macos_runner_workers": macos,
        "vm_runner_workers": vm_workers,
        "quiescence": quiescence,
        "physical_host_exclusive": not problems,
        "problems": problems,
    }
    host_gate.write_atomic(paths["root"] / f"assertion-{ident.key}.json", verdict)
    print(json.dumps(verdict, indent=2, default=str))
    return EXIT_OK if not problems else EXIT_INCONSISTENT
