"""Controls for the lifecycle: release on every outcome, no lock outliving its owner, drain."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import host_gate
import host_gate_config
from _host_gate_support import (
    CI_WORKFLOW,
    CODE_REPO,
    FAST,
    STARTED_WORKERS,
    Job,
    admitted,
    all_free,
    check,
    fresh,
    locks,
    ordinary,
    refusal,
    refuses,
    slo,
    within,
)
from arbiter_error import ArbiterError

HERE = Path(__file__).resolve().parent


def test_completion_releases_on_every_path() -> None:
    print("\ncompletion releases on every outcome (§6)")
    for outcome in ("success", "workflow failure", "cancelled",
                    "benchmark INCONCLUSIVE", "benchmark FAIL"):
        paths = fresh()
        owner = admitted(paths, slo())
        host_gate.activate(paths, slo(), {"established": True, "duration_s": 1})
        host_gate.job_completed(paths, slo())
        freed = within(lambda: locks(paths)["gate"] == "free" and locks(paths)["host"] == "free")
        check(f"locks released after {outcome}", freed is not None)
        check(f"file gate RELEASED after {outcome}",
              host_gate.read_gate(paths)["state"] == host_gate.RELEASED)
        check(f"normal admission resumes after {outcome}",
              refusal(paths, ordinary(9)) is None)
        owner.end()


def _gate_state(paths) -> str:
    return host_gate.read_gate(paths)["state"]


def _a_live_owner_stays_closed_then_worker_dies() -> None:
    # A LIVE owner keeps the host closed, however old its record looks.
    paths = fresh()
    owner = admitted(paths, slo())
    gate = host_gate.read_gate(paths)
    host_gate.write_atomic(paths["gate"], {**gate, "created_at": "2000-01-01T00:00:00Z"})
    check("age alone does NOT release a live owner's reservation",
          refusal(paths, ordinary(5)) is not None, "an old reservation opened")

    # The owner's WORKER dies (kill -9, crash, runner stopped): everything goes at once.
    owner.worker.kill()
    freed = within(lambda: all_free(paths))
    check("kill -9 of the worker frees every lock", freed is not None)
    check("  (within 1 s)", freed is not None and freed < 1.0, f"{freed}")
    check("and the holder marks the file gate RELEASED on its way out",
          within(lambda: _gate_state(paths) == host_gate.RELEASED) is not None)
    check("ordinary work is admitted behind it", refusal(paths, ordinary(6)) is None)
    owner.end()


def _a_killed_holder_leaves_a_stale_gate() -> None:
    # The HOLDER itself is killed -9: the kernel frees its locks; nothing else runs.
    paths = fresh()
    owner = admitted(paths, slo())
    owner.holder.kill()
    freed = within(lambda: all_free(paths))
    check("kill -9 of the holder frees every lock", freed is not None)
    check("  (within 1 s)", freed is not None and freed < 1.0, f"{freed}")
    check("the file gate is left stale (nobody could write it)",
          _gate_state(paths) == host_gate.RESERVING)
    check("the next admission repairs it and is admitted", refusal(paths, ordinary(7)) is None)
    check("the file gate then reads RELEASED", _gate_state(paths) == host_gate.RELEASED)
    owner.end()


def _a_dead_ordinary_job_does_not_block_a_drain() -> None:
    # An ordinary job whose worker dies frees its share of the host at once, so an SLO
    # drain does not wait on a dead job.
    paths = fresh()
    dead = admitted(paths, ordinary(8))
    dead.worker.kill()
    freed = within(lambda: locks(paths)["host"] == "free")
    check("a dead ordinary job's host lock is freed", freed is not None)
    later = Job(paths, slo(80))
    try:
        later.admit(drain_wait=2)
        check("so an SLO drains straight past it", True)
    except ArbiterError as exc:
        check("so an SLO drains straight past it", False, str(exc))
    later.end()
    dead.end()


def test_crash_leaves_closed_not_open() -> None:
    print("\nkilled jobs, killed holders: no lock outlives its owner (§6)")
    _a_live_owner_stays_closed_then_worker_dies()
    _a_killed_holder_leaves_a_stale_gate()
    _a_dead_ordinary_job_does_not_block_a_drain()


def test_drain_refusal_names_the_blocker() -> None:
    """A drain that gives up must say WHICH job held the host, and release it.

    The reservation closes the host to every runner from the moment it is granted, so a
    drain that cannot complete is a fleet-wide outage until it expires. On 2026-09-12 that
    ran most of an hour. The bound must be short, and the refusal must name the blocker.
    """
    print("\na drain that gives up names the blocker and releases (blast radius)")
    check("the drain bound is at most 30 minutes", host_gate_config.DRAIN_WAIT_S <= 30 * 60,
          f"{host_gate_config.DRAIN_WAIT_S}s")
    paths = fresh()
    blocker = admitted(paths, ordinary(7, runner="dev1"))
    message = refusal(paths, slo(), drain_wait=1)
    check("the drain refuses when work will not finish", message is not None, "it was admitted")
    message = message or ""
    check("and the refusal NAMES the blocking job", ordinary(7, runner="dev1").key in message,
          message[:200])
    check("and says no workload ran", "executed no workload" in message, message[:200])
    check("the blocking work was NOT killed", blocker.worker.poll() is None)
    check("the reservation is released so ordinary work resumes",
          _gate_state(paths) == host_gate.RELEASED)
    check("and a new ordinary job is admitted again", refusal(paths, ordinary(8)) is None)
    blocker.end()


def test_mirror_is_published_for_the_other_kernel() -> None:
    print("\nthe committed mirror the VM reads (cross-kernel rule)")
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    check("the mirror exists", paths["mirror_gate"].exists())
    mirrored = json.loads(paths["mirror_gate"].read_text())
    authoritative = json.loads(paths["gate"].read_text())
    check("the mirror matches the authoritative record",
          mirrored["reservation_id"] == authoritative["reservation_id"])
    check("the mirror names the OWNER, not merely a boolean",
          mirrored.get("owner", {}).get("runner") == "dev1-mcp-re")
    check("the reservation carries id, state and creation time",
          all(mirrored.get(k) for k in ("state", "reservation_id", "created_at")))
    check("and stale-recovery information", bool(mirrored.get("stale_recovery")))
    host_gate.job_completed(paths, slo())
    check("release is mirrored too",
          json.loads(paths["mirror_gate"].read_text())["state"] == host_gate.RELEASED)


def test_vm_reported_jobs_block_drain() -> None:
    print("\nthe VM's own report participates in drain")
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    (paths["vm_active"] / "dev1-linux-77-1-build.json").write_text(json.dumps({
        "key": "dev1-linux-77-1-build",
        "identity": {"runner": "dev1-linux", "job": "build"},
        "started_at": host_gate.now()}))
    records = host_gate.active_records(paths)
    check("a VM-reported job appears in the active set", len(records) == 1)
    check("and is labelled as VM-reported", records[0]["reported_by"] == "vm")
    check("a VM-reported job blocks the drain",
          refuses(lambda: host_gate.await_drain(paths, slo(), lambda: 0, wait_s=2)),
          "drain succeeded")


def test_the_holder_needs_something_to_watch() -> None:
    print("\na holder with nothing to watch takes no lock")
    paths = fresh()
    ghost = subprocess.Popen(["true"])
    ghost.wait()
    try:
        host_gate.admit_job(paths, ordinary(30), host_gate.Watch(ghost.pid), bounds=FAST)
        check("a job whose worker is already gone is refused", False, "admitted")
    except ArbiterError as exc:
        check("a job whose worker is already gone is refused", "already gone" in str(exc), str(exc))
    check("and no lock is held", all_free(paths))


def _hook_script(paths, worker_pid: int) -> str:
    return "\n".join([
        "import sys",
        "from pathlib import Path",
        f"sys.path.insert(0, {str(HERE)!r})",
        "import host_gate",
        "from job_identity import JobIdentity",
        f"p = host_gate.paths(Path({str(paths['root'])!r}), Path({str(paths['mirror'])!r}))",
        "host_gate.ensure_layout(p)",
        f"ident = JobIdentity('dev1-fast-1', {CODE_REPO!r}, '', {CI_WORKFLOW!r}, '40', '1', 'fast')",
        f"host_gate.admit_job(p, ident, host_gate.Watch({worker_pid}), bounds={FAST!r})",
        "print('admitted')",
    ])


def _run_the_hook_like_the_runner(paths, worker) -> None:
    """Run an admission and read its output to EOF, as the runner does."""
    hook = subprocess.Popen([sys.executable, "-c", _hook_script(paths, worker.pid)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = hook.communicate(timeout=20)
        check("the hook's output reaches EOF while its holder lives",
              b"admitted" in out, (out + err).decode()[-300:])
    except subprocess.TimeoutExpired:
        # Do NOT communicate() again: a holder holding the pipe would stall that too.
        hook.kill()
        hook.stdout.close()
        hook.stderr.close()
        hook.wait()
        subprocess.run(["pkill", "-f", f"--watch {worker.pid} "], capture_output=True)
        check("the hook's output reaches EOF while its holder lives", False, "stalled")


def test_the_hook_returns_while_the_holder_lives() -> None:
    """The runner reads a hook's stdout and stderr to EOF. A holder that kept either open
    would stall every job at "Set up job"; this runs an admission exactly that way."""
    print("\nthe hook returns at once; the holder keeps the lock")
    paths = fresh()
    worker = subprocess.Popen(["sleep", "600"])
    STARTED_WORKERS.append(worker)
    _run_the_hook_like_the_runner(paths, worker)
    check("and the lock is still held after the hook has exited",
          locks(paths)["host"] == "shared")
    worker.kill()
    worker.wait()
    check("until the worker exits", within(lambda: locks(paths)["host"] == "free") is not None)
