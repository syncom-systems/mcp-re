# SPDX-License-Identifier: Apache-2.0
"""The host-local replay tier: one Redis primary and two replicas as plain processes.

The proxy's admission path under test is `redis-wait-quorum:2:2000`, so the tier must have
two replicas that ACKNOWLEDGE writes, not merely two that are attached. The configuration is
the one the canonical Job sidecars run (`redis-server --port P --appendonly yes`, defaults
otherwise), bound to loopback, on the registry's ports. It is brought up once and kept for
the whole campaign, so every point measures the same tier, and its INFO is captured around
every point so a plateau that coincides with replay-tier load is visible as such.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from common import log, write_json

ROLES = ("primary", "replica-1", "replica-2")
PORT_KEYS = {"primary": "mcp_re_redis", "replica-1": "mcp_re_redis_replica_1", "replica-2": "mcp_re_redis_replica_2"}


class TierError(RuntimeError):
    pass


def cli(port: int, *args: str, timeout: float = 10) -> str:
    out = subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", str(port), *args],
                         capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise TierError(f"redis-cli -p {port} {' '.join(args)}: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def parse_info(text: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            key, _, value = line.partition(":")
            info[key] = value
    return info


class Tier:
    def __init__(self, run_dir: Path, port_map: dict[str, int]):
        self.dir = run_dir / "redis"
        self.ports = {role: port_map[key] for role, key in PORT_KEYS.items()}
        self.procs: dict[str, subprocess.Popen] = {}

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.ports['primary']}"

    def argv(self, role: str) -> list[str]:
        data = self.dir / "data" / role
        argv = ["redis-server", "--port", str(self.ports[role]), "--bind", "127.0.0.1",
                "--protected-mode", "yes", "--appendonly", "yes", "--dir", str(data),
                "--logfile", str(self.dir / f"{role}.log")]
        if role != "primary":
            argv += ["--replicaof", "127.0.0.1", str(self.ports["primary"])]
        return argv

    def up(self, run_dir: Path) -> None:
        if shutil.which("redis-server") is None or shutil.which("redis-cli") is None:
            raise TierError("redis-server/redis-cli are not installed")
        for role in ROLES:
            (self.dir / "data" / role).mkdir(parents=True, exist_ok=True)
            self.procs[role] = subprocess.Popen(self.argv(role), stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL, start_new_session=True)
        write_json(self.dir / "tier.json", {"url": self.url, "ports": self.ports,
                                            "argv": {r: self.argv(r) for r in ROLES},
                                            "pids": {r: p.pid for r, p in self.procs.items()}})
        self.wait_quorum()
        log(run_dir, f"redis tier: primary + 2 replicas acknowledging WAIT 2 on {self.url}")

    def wait_quorum(self, deadline_s: float = 60) -> None:
        """Both replicas attached AND acknowledging: WAIT 2 must return 2."""
        primary = self.ports["primary"]
        end = time.monotonic() + deadline_s
        last = ""
        while time.monotonic() < end:
            try:
                info = parse_info(cli(primary, "info", "replication"))
                if int(info.get("connected_slaves", "0")) >= 2:
                    cli(primary, "set", "__ceiling_quorum_probe", "1")
                    acked = cli(primary, "wait", "2", "500").strip()
                    if acked.isdigit() and int(acked) >= 2:
                        cli(primary, "del", "__ceiling_quorum_probe")
                        return
                    last = f"WAIT 2 returned {acked}"
                else:
                    last = f"{info.get('connected_slaves', '0')} replica(s) attached"
            except (TierError, subprocess.TimeoutExpired) as exc:
                last = str(exc)
            time.sleep(0.5)
        raise TierError(f"quorum 2 not met within {deadline_s}s: {last}")

    def health(self) -> dict:
        """Replication health in one record: roles, link status, offset lag."""
        out: dict[str, dict] = {}
        for role in ROLES:
            try:
                info = parse_info(cli(self.ports[role], "info", "replication"))
            except (TierError, subprocess.TimeoutExpired) as exc:
                out[role] = {"error": str(exc)}
                continue
            out[role] = {k: info.get(k) for k in ("role", "connected_slaves", "master_link_status",
                                                 "master_repl_offset", "slave_repl_offset", "master_sync_in_progress")}
        return out

    def snapshot(self, path: Path) -> dict:
        """INFO all + SLOWLOG + LATENCY LATEST of every node, written to path."""
        record: dict[str, dict] = {}
        for role in ROLES:
            port = self.ports[role]
            try:
                record[role] = {
                    "info": parse_info(cli(port, "info", "all")),
                    "slowlog": cli(port, "slowlog", "get", "16"),
                    "latency_latest": cli(port, "latency", "latest"),
                }
            except (TierError, subprocess.TimeoutExpired) as exc:
                record[role] = {"error": str(exc)}
        write_json(path, record)
        return record

    def down(self) -> None:
        for role in reversed(ROLES):
            proc = self.procs.get(role)
            if proc is None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.procs.clear()
