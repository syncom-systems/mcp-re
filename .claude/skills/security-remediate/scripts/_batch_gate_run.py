"""Running one gate command to a log, and reading the tail of that log."""
from __future__ import annotations

import subprocess


def run(cmd: list[str], log: str) -> int:
    with open(log, "w", encoding="utf-8") as fh:
        return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode


def tail(log: str, n: int = 6) -> list[str]:
    return open(log, encoding="utf-8", errors="replace").read().strip().splitlines()[-n:]
