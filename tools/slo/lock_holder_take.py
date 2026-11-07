"""The lock-taking thread of `lock_holder`.

It owns the blocking `flock` calls. Progress reaches the holder's main thread as lines on a
pipe: `P<i>` before step `i` blocks, `G` once the exclusive gate is held, `OK` when every step
is done, `E<reason>` when one failed. The main thread never blocks on a lock; it only reads
these lines.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

import host_locks


class LockTaker:
    """Runs a plan's steps in order, reporting each one on `notify_w`."""

    def __init__(self, root: Path, steps: list, notify_w: int) -> None:
        self._root = root
        self._steps = steps
        self._notify_w = notify_w
        self._held: dict[str, int] = {}

    def run(self) -> None:
        try:
            for index, step in enumerate(self._steps):
                if step[0] == "take":
                    self._take(index, step)
                else:
                    self._release(step[1])
            os.write(self._notify_w, b"OK\n")
        except OSError as exc:
            os.write(self._notify_w, f"E{exc}\n".encode())

    def _take(self, index: int, step: tuple) -> None:
        _, name, mode, _bound = step
        os.write(self._notify_w, f"P{index}\n".encode())
        fd = os.open(host_locks.lock_path(self._root, name), os.O_RDWR | os.O_CREAT, 0o644)
        self._held[name] = fd
        fcntl.flock(fd, mode)
        if name == "gate" and mode == host_locks.EX:
            os.write(self._notify_w, b"G\n")

    def _release(self, name: str) -> None:
        fd = self._held.pop(name)
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
