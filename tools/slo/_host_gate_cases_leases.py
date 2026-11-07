"""Controls for the heavy slot and for `local-lease`, which takes it by hand."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import host_gate_config
import host_locks
from _host_gate_support import (
    ARBITER,
    CI_WORKFLOW,
    MCPRE_REPO,
    Job,
    admitted,
    all_free,
    check,
    fresh,
    in_thread,
    locks,
    ordinary,
    refusal,
    within,
    workflow_ref,
)
from job_identity import JobIdentity


@contextmanager
def heavy_runners(names: frozenset):
    """Run with `names` as the runners the heavy slot serializes."""
    saved = host_gate_config.HEAVY_RUNNERS
    host_gate_config.HEAVY_RUNNERS = names
    try:
        yield
    finally:
        host_gate_config.HEAVY_RUNNERS = saved


def _a_second_heavy_job_waits(paths, mcpre: JobIdentity, code_bazel: Job) -> None:
    message = refusal(paths, mcpre)
    check("a second heavy job waits (and refuses at its bound)", message is not None,
          "admitted")
    check("the refusal names the holder", code_bazel.ident.key in (message or ""),
          str(message))
    check("the fast lane is admitted while the heavy slot is held",
          refusal(paths, ordinary(12, "dev1-fast-1")) is None)


def _the_waiter_gets_the_slot(paths, mcpre: JobIdentity, code_bazel: Job) -> None:
    # Whoever is already waiting gets the slot, not a later arrival.
    waiter = in_thread(lambda: admitted(paths, mcpre, heavy_wait=20))
    time.sleep(0.8)  # the waiter is now blocked on the heavy lock
    code_bazel.end()
    late = refusal(paths, ordinary(13, "dev1"), heavy_wait=1)
    waiter["thread"].join(10)
    check("the job already waiting gets the heavy slot", "result" in waiter,
          str(waiter.get("error")))
    check("a job arriving after it does not jump the queue", late is not None, "admitted")
    if "result" in waiter:
        waiter["result"].end()


def _a_dying_waiter_never_takes_the_lock() -> None:
    # A waiter whose job dies while it waits never takes the lock.
    paths = fresh()
    running = admitted(paths, ordinary(20, "dev1"))
    doomed = Job(paths, ordinary(21, "dev1-mcp-re"))
    box = in_thread(lambda: doomed.admit(heavy_wait=20))
    time.sleep(0.8)
    doomed.worker.kill()
    gone = within(lambda: "error" in box or "result" in box)
    check("a waiter whose worker dies gives up at once",
          gone is not None and "error" in box, f"{gone} {box}")
    running.end()
    check("and never takes the heavy lock afterwards",
          within(lambda: locks(paths)["heavy"] == "free") is not None
          and not host_locks.holders(paths["root"]))
    doomed.end()


def test_heavy_slot() -> None:
    print("\none heavy job on the host at a time; the fast lane is never in it")
    with heavy_runners(frozenset({"dev1", "dev1-mcp-re"})):
        paths = fresh()
        code_bazel = admitted(paths, ordinary(10, "dev1"))
        mcpre = JobIdentity("dev1-mcp-re", MCPRE_REPO, workflow_ref(MCPRE_REPO, CI_WORKFLOW),
                            CI_WORKFLOW, "11", "1", "verification")
        _a_second_heavy_job_waits(paths, mcpre, code_bazel)
        _the_waiter_gets_the_slot(paths, mcpre, code_bazel)
        _a_dying_waiter_never_takes_the_lock()


def lease(paths: dict, *command: str, **env: str) -> subprocess.Popen:
    """`runner-arbiter local-lease -- command...` against this test's temp root."""
    return subprocess.Popen(
        [sys.executable, str(ARBITER), "--root", str(paths["root"]),
         "--mirror", str(paths["mirror"]), "local-lease", "--", *command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "MCP_RE_ARBITER_LEASE_POLL_S": "0.3", **env})


def _heavy_is(paths, state: str) -> bool:
    return locks(paths)["heavy"] == state


def _the_lease_holds_the_slot_while_it_runs(paths, tmp: Path) -> None:
    seen = tmp / "seen"

    # Held while the command runs, as the heavy plan: heavy EX, host SH.
    proc = lease(paths, "sh", "-c", f'echo "$RUNNER_ARBITER_LEASE" > {seen}; sleep 2')
    held = within(lambda: seen.exists() and _heavy_is(paths, "exclusive"))
    check("the lease holds the heavy lock exclusively while its command runs",
          held is not None, str(locks(paths)))
    check("and the host lock shared, like an admitted job",
          locks(paths)["host"] == "shared", str(locks(paths)))
    keys = [h.get("key") for h in host_locks.holders(paths["root"])]
    check("its holder record is a local key, not a runner job's",
          any(str(k).startswith("local-") for k in keys), str(keys))
    check("the command is told it is inside a lease",
          within(lambda: seen.read_text().strip().startswith("local-")) is not None)
    proc.wait(10)
    check("the lock is released when the command ends",
          within(lambda: all_free(paths)) is not None, str(locks(paths)))

    # The exit status is the command's.
    proc = lease(paths, "sh", "-c", "exit 7")
    check("the command's exit status is returned", proc.wait(10) == 7, str(proc.returncode))


def _a_lease_waits_behind_a_heavy_ci_job(paths, tmp: Path) -> None:
    # Behind a heavy CI job: waits, says for whom, and starts only after it ends.
    ci = admitted(paths, ordinary(40, "dev1"))
    marker = tmp / "started"
    proc = lease(paths, "touch", str(marker))
    time.sleep(1.5)
    check("a lease behind a heavy CI job does not start its command",
          not marker.exists() and proc.poll() is None)
    ci.end()
    out, err = proc.communicate(timeout=10)
    check("it names the CI job it is waiting for", ci.ident.key in err, err)
    check("and runs once that job ends", proc.returncode == 0 and marker.exists(),
          f"{proc.returncode} {err}")

    # A CI job arriving during a lease waits for it: the exclusion is mutual.
    proc = lease(paths, "sleep", "3")
    within(lambda: _heavy_is(paths, "exclusive"))
    check("a heavy CI job is refused at its bound while a lease holds the slot",
          refusal(paths, ordinary(41, "dev1")) is not None)
    proc.wait(10)


def _a_lease_cannot_leave_the_lock_behind(paths) -> None:
    # SIGTERM to the lease reaches the command and ends the lease.
    proc = lease(paths, "sleep", "60")
    within(lambda: _heavy_is(paths, "exclusive"))
    time.sleep(0.3)
    proc.terminate()
    code = proc.wait(10)
    check("SIGTERM is forwarded to the command", code == 128 + 15, str(code))
    check("and the lock is released",
          within(lambda: _heavy_is(paths, "free")) is not None, str(locks(paths)))

    # A lease killed outright cannot leave the lock behind.
    proc = lease(paths, "sleep", "60")
    within(lambda: _heavy_is(paths, "exclusive"))
    proc.kill()
    proc.wait()
    check("a SIGKILLed lease leaves no lock behind",
          within(lambda: _heavy_is(paths, "free")) is not None, str(locks(paths)))


def test_local_lease() -> None:
    print("\na command run by hand takes the heavy slot, waits for CI, and lets go on exit")
    with heavy_runners(frozenset({"dev1"})):
        paths = fresh()
        tmp = Path(tempfile.mkdtemp())
        _the_lease_holds_the_slot_while_it_runs(paths, tmp)
        _a_lease_waits_behind_a_heavy_ci_job(paths, tmp)
        _a_lease_cannot_leave_the_lock_behind(paths)
