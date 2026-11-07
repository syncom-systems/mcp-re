"""Controls for the ordering that closes the race: reserve, drain, and the fail-closed paths."""

from __future__ import annotations

import time

import host_gate
from _host_gate_support import (
    Job,
    admitted,
    check,
    finished,
    fresh,
    in_thread,
    locks,
    ordinary,
    refusal,
    refuses,
    slo,
    within,
)
from arbiter_error import ArbiterError


def _reservation_taken(paths) -> bool:
    return host_gate.read_gate(paths).get("state") == host_gate.RESERVING


def test_reserve_then_drain() -> None:
    print("\nreserve-first-then-drain (§2)")
    paths = fresh()
    first = admitted(paths, ordinary(1))
    owner = in_thread(lambda: admitted(paths, slo(), drain_wait=20))
    reserved = within(lambda: _reservation_taken(paths))
    check("the reservation is taken while a job is still running", reserved is not None)

    # The invariant: after the grant, NO new non-owner job may be admitted -- which is what
    # stops the queue refilling while the owner waits for the drain.
    check("a new ordinary job is refused during a reservation",
          refusal(paths, ordinary(2)) is not None, "it was admitted")
    check("the pre-existing job is left running", first.worker.poll() is None)
    check("the owner is still draining", not finished(owner))

    first.end()
    drained = within(lambda: finished(owner))
    check("the drain completes the moment the running job ends",
          drained is not None and "result" in owner, str(owner.get("error")))
    check("  (within 1 s of the job ending)", drained is not None and drained < 1.0,
          f"{drained}")
    check("the owner then holds gate and host exclusively",
          locks(paths)["gate"] == "exclusive" and locks(paths)["host"] == "exclusive")
    if "result" in owner:
        owner["result"].end()


def test_ordinary_first_then_slo() -> None:
    print("\nordinary first, then the SLO (§13)")
    paths = fresh()
    first = admitted(paths, ordinary(1))
    owner = in_thread(lambda: admitted(paths, slo(), drain_wait=20))
    within(lambda: _reservation_taken(paths))
    gate = host_gate.read_gate(paths)
    check("the reservation is granted even over a running job",
          gate["state"] == host_gate.RESERVING)
    check("but the owner is not yet RESERVED", gate["state"] != host_gate.RESERVED)
    host_gate.job_completed(paths, ordinary(1))
    within(lambda: finished(owner))
    check("the owner is admitted once the ordinary job completes", "result" in owner,
          str(owner.get("error")))
    if "result" in owner:
        host_gate.activate(paths, slo(), {"established": True, "duration_s": 60})
    check("the owner then reaches RESERVED",
          host_gate.read_gate(paths)["state"] == host_gate.RESERVED)
    first.end()
    if "result" in owner:
        owner["result"].end()


def test_second_slo_cannot_overlap() -> None:
    print("\ntwo SLO measurements cannot overlap (§13)")
    paths = fresh()
    one = admitted(paths, slo(1))
    check("a second SLO is refused while the first holds the host",
          refusal(paths, slo(2)) is not None, "it was admitted")
    check("the file gate still names the first owner",
          host_gate.read_gate(paths)["owner"]["key"] == slo(1).key)
    one.end()
    two = Job(paths, slo(2))
    try:
        two.admit()
        check("the second SLO is admitted once the first has ended", True)
    except ArbiterError as exc:
        check("the second SLO is admitted once the first has ended", False, str(exc))
    two.end()


def _simultaneous_round(r: int) -> tuple[bool, bool]:
    """One concurrent admission: (the SLO was admitted beside a running job, nobody was)."""
    paths = fresh()
    jobs = [Job(paths, slo(500 + r))] + [Job(paths, ordinary(i)) for i in range(5)]
    boxes = [in_thread(lambda j=j: j.admit(gate_wait=1, drain_wait=1)) for j in jobs]
    for b in boxes:
        b["thread"].join(30)
    ok = ["result" in b for b in boxes]
    for j in jobs:
        j.end()
    # THE forbidden state: the SLO admitted while any ordinary job is admitted and still
    # running. Every stand-in worker is alive here, so any overlap would be live.
    return ok[0] and any(ok[1:]), not any(ok)


def test_simultaneous_admission() -> None:
    print("\nsimultaneous admission, driven concurrently (§13)")
    rounds = 8
    outcomes = [_simultaneous_round(r) for r in range(rounds)]
    violations = sum(1 for overlapped, _ in outcomes if overlapped)
    empty = sum(1 for _, nobody in outcomes if nobody)
    check(f"no round admitted the SLO beside a running job ({rounds} rounds)",
          violations == 0, f"{violations} violations")
    check("and every round admitted someone (the positive control)", empty == 0,
          f"{empty} empty rounds")


def _unobservable() -> int:
    raise ArbiterError("VM unreachable")


def _refuses_drain(observe) -> bool:
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    return refuses(lambda: host_gate.await_drain(paths, slo(), observe, wait_s=2))


def test_fail_closed() -> None:
    print("\nfail-closed (§5)")
    paths = fresh()
    owner = admitted(paths, slo())
    start = time.monotonic()
    check("a bounded wait ends in refusal, not admission",
          refusal(paths, ordinary(3), gate_wait=2) is not None, "admitted")
    check("the wait was actually bounded", time.monotonic() - start < 20)
    owner.end()

    # A corrupt gate must not read as an open host. This is THE fail-open case.
    corrupt = fresh()
    corrupt["gate"].write_text("{ not json")
    check("a corrupt gate refuses rather than reading as OPEN",
          refuses(lambda: host_gate.read_gate(corrupt)), "parsed")

    # An unobservable VM must refuse too: "cannot see" is not "is idle".
    check("an unobservable VM refuses the drain", _refuses_drain(_unobservable),
          "drain succeeded")

    # A busy VM blocks the drain even when macOS looks completely clear -- the case a
    # macOS-only pgrep can never see.
    check("a busy VM blocks the drain though macOS is clear", _refuses_drain(lambda: 2),
          "drain succeeded")
