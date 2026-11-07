"""One lock holder's run: watches, the lock-taking thread, and the wait loop.

`lock_holder` explains the structure; this module is the process behind it. Every way out is
`finish`, which is `os._exit`: the kernel releases the locks, so no path has to remember to.
"""

from __future__ import annotations

import json
import os
import select
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import host_gate
import host_locks
from lock_holder_take import LockTaker

MODE_NAME = {host_locks.SH: "shared", host_locks.EX: "exclusive"}


@dataclass(frozen=True)
class HolderConfig:
    """What the command line told this holder to do."""

    root: Path
    mirror: Path
    key: str
    plan: str
    bounds: dict
    record: str
    watch: int
    hook: int
    ready_fd: int


class Holder:
    def __init__(self, config: HolderConfig) -> None:
        self._config = config
        self._paths = host_gate.paths(config.root, config.mirror)
        self._steps = host_locks.PLANS[config.plan]
        self._record_path = config.root / "holders" / f"{config.key}.json"
        self._answered = False
        self._admitted = False
        self._deadline: float | None = None
        self._waiting_for = ""
        self._buffer = b""
        self._watched = {config.watch: "the job's Runner.Worker",
                         config.hook: "the admission hook"}
        self._queue = select.kqueue()
        self._notify_r, self._notify_w = os.pipe()

    def run(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self._on_signal)
        self._watch_processes()
        self._queue.control(
            [select.kevent(self._notify_r, select.KQ_FILTER_READ, select.KQ_EV_ADD)], 0)
        taker = LockTaker(self._config.root, self._steps, self._notify_w)
        threading.Thread(target=taker.run, daemon=True).start()
        while True:
            self._wait_once()

    def _answer(self, line: str) -> None:
        if self._answered:
            return
        self._answered = True
        fd = self._config.ready_fd
        try:
            os.write(fd, (line + "\n").encode())
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass

    def _finish(self, code: int) -> None:
        """End the process. The kernel releases every lock this process holds."""
        try:
            if json.loads(self._record_path.read_text()).get("pid") == os.getpid():
                self._record_path.unlink()
        except (OSError, ValueError):
            pass
        if self._config.plan == "slo":
            try:
                host_gate.release_owner(self._paths, self._config.key,
                                        "the SLO job's lock holder exited")
            except Exception:  # noqa: BLE001 -- the process is ending either way
                pass
        os._exit(code)

    def _on_signal(self, signum, _frame) -> None:
        self._answer(f"REFUSED: the lock holder was stopped (signal {signum}) before admission")
        self._finish(0)

    def _watch_processes(self) -> None:
        for pid, what in self._watched.items():
            try:
                self._queue.control([select.kevent(pid, select.KQ_FILTER_PROC,
                                                   select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                                   select.KQ_NOTE_EXIT)], 0)
            except OSError:
                self._answer(f"REFUSED: {what} (pid {pid}) was already gone; "
                             "nothing to hold a lock for")
                self._finish(0)

    def _wait_once(self) -> None:
        events = self._queue.control(None, 4, self._timeout())
        if not events and self._timed_out():
            self._refuse_unadmitted_wait()
        for event in events:
            if event.filter == select.KQ_FILTER_PROC:
                self._on_process_exit(event.ident)
            elif event.ident == self._notify_r:
                self._on_notification()

    def _timeout(self) -> float | None:
        if self._admitted or self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    def _timed_out(self) -> bool:
        return (not self._admitted and self._deadline is not None
                and time.monotonic() >= self._deadline)

    def _refuse_unadmitted_wait(self) -> None:
        others = ", ".join(f"{h.get('key')} ({h.get('plan')})"
                           for h in host_locks.holders(self._config.root)
                           if h.get("key") != self._config.key)
        self._answer(f"REFUSED: waited {self._waiting_for} and it was not granted. Holders "
                     f"now: {others or 'none recorded'}. Fail-closed: this job executed no "
                     "workload.")
        self._finish(3)

    def _is_admitted_hook(self, pid: int) -> bool:
        config = self._config
        return self._admitted and pid == config.hook and config.hook != config.watch

    def _on_process_exit(self, pid: int) -> None:
        if self._is_admitted_hook(pid):
            return  # the hook ends normally right after admission
        self._answer(f"REFUSED: {self._watched.get(pid, 'a watched process')} exited "
                     "before admission")
        self._finish(0)

    def _on_notification(self) -> None:
        self._buffer += os.read(self._notify_r, 4096)
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            self._on_line(line)

    def _on_line(self, line: bytes) -> None:
        if line.startswith(b"P"):
            self._start_waiting(int(line[1:]))
        elif line == b"G":
            self._announce_gate()
        elif line == b"OK":
            self._admit()
        elif line.startswith(b"E"):
            self._answer(f"REFUSED: taking the locks failed: {line[1:].decode()}")
            self._finish(3)

    def _start_waiting(self, index: int) -> None:
        _, name, mode, bound = self._steps[index]
        seconds = int(self._config.bounds[bound])
        self._deadline = time.monotonic() + seconds
        self._waiting_for = f"{seconds}s for the {name} lock ({MODE_NAME[mode]})"

    def _announce_gate(self) -> None:
        try:
            os.write(self._config.ready_fd, b"GATE\n")
        except OSError:
            pass

    def _admit(self) -> None:
        config = self._config
        self._record_path.parent.mkdir(parents=True, exist_ok=True)
        host_gate.write_atomic(self._record_path, {
            **json.loads(config.record), "pid": os.getpid(), "key": config.key,
            "plan": config.plan, "watch": config.watch, "admitted_at": host_gate.now()})
        self._admitted = True
        self._deadline = None
        self._answer("ADMITTED")
