"""Participation: an unhooked runner is unobserved, not quiet.

The owner refuses to measure unless every registered runner application is known to consult
the gate before admitting work. Each runner is judged from direct evidence where there is
any, from its `.env` and listener otherwise, and refused where neither can be established.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
import job_liveness  # noqa: E402

_HOOK_VAR = "ACTIONS_RUNNER_HOOK_JOB_STARTED"


@dataclass(frozen=True)
class VmProbes:
    """What can be asked of the VM runner. `read_env=None` means the VM cannot be reached."""

    read_env: Callable[[str], str] | None = None
    check_exec: Callable[[str], bool] | None = None
    check_fresh: Callable[[], bool | None] | None = None
    stopped: bool = False


def hook_from_env_text(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip().startswith(f"{_HOOK_VAR}="):
            return line.split("=", 1)[1].strip()
    return None


def _parse_etime(elapsed: str) -> int:
    """Seconds from `ps -o etime=` output: `[[dd-]hh:]mm:ss`."""
    days, _, clock = elapsed.rpartition("-") if "-" in elapsed else ("", "", elapsed)
    units = [int(x) for x in clock.split(":")]
    return (int(days) * 86400 if days else 0) + sum(
        value * scale for value, scale in zip(reversed(units), (1, 60, 3600)))


def _listener_pid(runner_root: str) -> str | None:
    try:
        found = subprocess.run(["pgrep", "-f", f"{runner_root}/bin/Runner.Listener"],
                               capture_output=True, text=True)
    except OSError:
        return None
    pids = [p for p in found.stdout.split() if p.strip().isdigit()]
    return pids[0] if pids else None


def _listener_age_s(pid: str) -> int | None:
    # ELAPSED time, not a formatted start date.
    #
    # This read `ps -o lstart=` and parsed it with `time.strptime` + `time.mktime`. That
    # was wrong in a way that only appeared inside a runner job: `ps` prints the start in
    # LOCAL time while `mktime` interprets it in the PROCESS's timezone, so a hook running
    # without TZ set resolved 21:19 CEST as 21:19 UTC -- two hours early, which put the
    # listener before the 21:18 .env and reported a correctly-hooked runner as not
    # participating. It refused a real SLO run on 2026-09-12 at 06:08.
    #
    # `etime` is elapsed seconds since start. It has no timezone, no locale-dependent month
    # name and no date format, so the class of bug cannot recur here.
    try:
        elapsed = subprocess.run(["ps", "-o", "etime=", "-p", pid],
                                 capture_output=True, text=True).stdout.strip()
        return _parse_etime(elapsed) if elapsed else None
    except (OSError, ValueError):
        return None


def listener_started_after_env(runner_root: str) -> bool | None:
    """Has the RUNNING listener actually loaded the current .env?

    Declaring the hook is not the same as enforcing it. A runner reads `.env` once, at
    listener startup, so a listener older than the file is running WITHOUT the hook while
    the file on disk says otherwise -- the precise shape of a fail-open: a config that
    reads as safe and a process that is not. Measured on dev1 2026-09-10, where the hook
    was written at 21:18 and the listener had been up since Sep 3.

    None means "cannot tell", which callers must treat as not-participating rather than as
    participating.
    """
    try:
        env_mtime = Path(runner_root, ".env").stat().st_mtime
    except OSError:
        return None
    pid = _listener_pid(runner_root)
    if pid is None:
        return None
    age = _listener_age_s(pid)
    return None if age is None else (time.time() - age) >= env_mtime


def runner_is_stopped(runner_root: str, table_fn=job_liveness.process_table) -> bool:
    """True only when NO listener or worker of this runner application is running.

    A stopped runner runs nothing, so it is quiet; and if launchd starts it again, the new
    listener reads the `.env` that declares the hook, so the gate governs it from its first
    job. An unreadable process table is not "stopped".
    """
    table = job_liveness.readable_table(table_fn)
    if table is None:
        return False
    pattern = re.compile(re.escape(runner_root) + r"/bin[^/]*/Runner\.(Listener|Worker)\b")
    return not any(pattern.search(command) for _, _, command in table.values())


def _running_from_own_hook(runner_name: str) -> bool:
    # DIRECT EVIDENCE beats inference. If this code is executing, it was
    # launched BY a runner's job-started hook -- so for THAT runner, the
    # question "has the listener loaded the hook configuration?" is already
    # answered in the affirmative by our own existence. Asking a timestamp
    # heuristic instead is strictly weaker and was observed to disagree: the
    # SLO job on dev1-mcp-re refused itself while running from dev1-mcp-re's
    # own hook, which is a contradiction the heuristic cannot represent.
    return os.environ.get("RUNNER_NAME") == runner_name and bool(os.environ.get(_HOOK_VAR))


def _judge_darwin_listener(entry: dict, hook_present: bool, fresh: bool | None) -> None:
    if not hook_present:
        entry["detail"] = f"no {_HOOK_VAR}, or hook absent"
    elif fresh is None:
        entry["detail"] = "no running listener found, or its start time is unreadable"
    elif not fresh:
        entry["detail"] = ("the hook is declared but this listener predates the "
                           ".env that declares it — restart required before the "
                           "hook is in force")
    else:
        entry["participating"] = True


def _darwin_participation(entry: dict, runner: dict, table_fn) -> None:
    hook = hook_from_env_text(Path(runner["root"], ".env").read_text())
    entry["hook"] = hook
    if _running_from_own_hook(runner["name"]):
        entry.update(participating=True, listener_loaded_env=True,
                     detail="proven directly: this check is running from its hook")
        return
    hook_present = bool(hook and Path(hook).exists())
    if hook_present and runner_is_stopped(runner["root"], table_fn):
        entry.update(participating=True, stopped=True,
                     detail=("stopped: no listener or worker is running; its .env "
                             "declares the hook, so it is gated if it starts"))
        return
    fresh = listener_started_after_env(runner["root"])
    entry["listener_loaded_env"] = fresh
    _judge_darwin_listener(entry, hook_present, fresh)


def _judge_vm_listener(entry: dict, hook: str | None, vm: VmProbes, fresh: bool | None) -> None:
    if not hook:
        entry["detail"] = f"no {_HOOK_VAR} in the VM .env"
    elif not (vm.check_exec and vm.check_exec(hook)):
        entry["detail"] = "hook declared but not executable in the VM"
    elif fresh is None:
        entry["detail"] = "could not establish when the VM listener started"
    elif not fresh:
        entry["detail"] = ("the VM listener predates the .env declaring the "
                           "hook — restart required before it is in force")
    else:
        entry["participating"] = True


def _vm_participation(entry: dict, runner: dict, vm: VmProbes) -> None:
    if vm.read_env is None:
        if vm.stopped:
            entry.update(participating=True, stopped=True,
                         detail=("VM stopped (Lima reports Stopped): its runner can run "
                                 "nothing, and reads the committed gate if started"))
        else:
            entry["detail"] = "VM unreachable"
        return
    hook = hook_from_env_text(vm.read_env(f"{runner['root']}/.env"))
    entry["hook"] = hook
    fresh = vm.check_fresh() if vm.check_fresh else None
    entry["listener_loaded_env"] = fresh
    _judge_vm_listener(entry, hook, vm, fresh)


def _participation_of(runner: dict, vm: VmProbes, table_fn) -> dict:
    entry = {"name": runner["name"], "kernel": runner["kernel"], "participating": False,
             "hook": None, "detail": ""}
    try:
        if runner["kernel"] == "darwin":
            _darwin_participation(entry, runner, table_fn)
        else:
            _vm_participation(entry, runner, vm)
    except OSError as exc:
        entry["detail"] = str(exc)
    return entry


def verify_participation(vm: VmProbes | None = None,
                         table_fn=job_liveness.process_table) -> dict:
    """Confirm every registered runner consults this gate before admitting work.

    A runner application that is not running at all counts as participating when its
    `.env` declares an existing hook: it can run nothing now, and it is gated once started.
    Likewise a VM that Lima reports as Stopped -- but a VM that is running and merely
    unreachable is still unobserved, and refuses.
    """
    probes = vm or VmProbes()
    results = [_participation_of(r, probes, table_fn) for r in cfg.REGISTERED_RUNNERS]
    return {"all_participating": all(e["participating"] for e in results), "runners": results}


def macos_workers() -> list[int]:
    """Independent fail-safe, NOT the lock.

    Catches a broken hook install, a missing ACTIVE record, or an unknown fourth runner.
    Never sufficient on its own: it cannot see the VM's kernel, so it can never establish
    that the PHYSICAL host is exclusive.
    """
    try:
        r = subprocess.run(["pgrep", "-f", "Runner.Worker"], capture_output=True, text=True)
    except OSError:
        return []
    return [int(x) for x in r.stdout.split() if x.strip().isdigit()]
