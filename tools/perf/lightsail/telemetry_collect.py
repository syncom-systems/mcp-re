# SPDX-License-Identifier: Apache-2.0
"""The context manager around one measurement point: sysstat collectors plus the /proc sampler."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from telemetry_sampler import Sampler
from telemetry_summary import summarize

EXTERNAL = {
    "mpstat.txt": ["mpstat", "-P", "ALL", "1"],
    "pidstat.txt": ["pidstat", "-h", "-u", "-r", "-w", "-C", "mcp-re|mcp_re|tls_load|saturation|redis", "1"],
    "vmstat.txt": ["vmstat", "-t", "-w", "1"],
    "sar-net.txt": ["sar", "-n", "DEV,TCP,ETCP,SOCK", "1"],
}


def _snapshot(path: Path) -> None:
    parts = {}
    for name, argv in (("ss_summary", ["ss", "-s"]), ("sockstat", ["cat", "/proc/net/sockstat"]),
                       ("file_nr", ["cat", "/proc/sys/fs/file-nr"]), ("loadavg", ["cat", "/proc/loadavg"]),
                       ("netstat_s", ["sh", "-c", "netstat -s 2>/dev/null || nstat -az 2>/dev/null"])):
        if shutil.which(argv[0]) is None:
            continue
        try:
            parts[name] = subprocess.run(argv, capture_output=True, text=True, timeout=20).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
    path.write_text(json.dumps(parts, indent=2) + "\n")


class Telemetry:
    """Context manager around one measurement point: snapshots before/after, collectors
    and the sampler during. `require=True` refuses a host without /proc or sysstat."""

    def __init__(self, point_dir: Path, vcpus: int, require: bool, redis_roles: dict[int, str] | None = None):
        self.dir = point_dir / "telemetry"
        self.vcpus, self.require = vcpus, require
        self.redis_roles = redis_roles or {}
        self.external: list[subprocess.Popen] = []
        self.sampler: Sampler | None = None
        self.result: dict = {"available": False}

    def _start_external(self) -> None:
        for name, argv in EXTERNAL.items():
            if shutil.which(argv[0]):
                handle = open(self.dir / name, "w")
                self.external.append(subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                                                      env=dict(os.environ, LC_ALL="C", S_TIME_FORMAT="ISO")))

    def _refuse_if_required(self, linux: bool) -> None:
        missing = [argv[0] for argv in EXTERNAL.values() if shutil.which(argv[0]) is None]
        ready = linux and not missing
        if self.require and not ready:
            raise RuntimeError(f"telemetry required but unavailable (linux={linux}, missing={missing})")

    def __enter__(self) -> "Telemetry":
        self.dir.mkdir(parents=True, exist_ok=True)
        linux = os.path.isdir("/proc/self")
        self._refuse_if_required(linux)
        if not linux:
            self.result = {"available": False, "reason": "no /proc on this host (not Linux)"}
            return self
        _snapshot(self.dir / "before.json")
        self._start_external()
        self.sampler = Sampler(self.dir / "proc-samples.jsonl", redis_roles=self.redis_roles)
        self.sampler.start()
        return self

    def _stop_external(self) -> None:
        for proc in self.external:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def __exit__(self, *_exc: object) -> None:
        if self.sampler is not None:
            self.sampler.stop_event.set()
            self.sampler.join(timeout=10)
            self.result = summarize(self.sampler.samples, self.vcpus)
        self._stop_external()
        if os.path.isdir("/proc/self"):
            _snapshot(self.dir / "after.json")
        (self.dir / "summary.json").write_text(json.dumps(self.result, indent=2, sort_keys=True) + "\n")
