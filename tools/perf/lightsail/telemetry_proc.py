# SPDX-License-Identifier: Apache-2.0
"""Reading /proc: process categories, parsers, and the schedstat watch groups."""

from __future__ import annotations

import os

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

#: process category by executable basename prefix. Order matters: the first match wins.
CATEGORIES = (
    ("proxy", ("mcp-re-proxy", "mcp_re_proxy")),
    ("bench", ("tls_load_harness_bench",)),
    ("loadgen", ("saturation_loadgen",)),
    ("backend", ("saturation_backend",)),
    ("rig", ("saturation_rig",)),
    # Debian/Ubuntu install redis-server as a symlink to redis-check-rdb, so the resolved
    # executable names the checker; the process name (comm) still says redis-server.
    ("redis", ("redis-server", "redis-check-rdb")),
    ("telemetry", ("mpstat", "pidstat", "vmstat", "sar", "sadc")),
)

def categorize(name: str) -> str:
    for category, prefixes in CATEGORIES:
        if any(name.startswith(p) for p in prefixes):
            return category
    return "other"



def read_text(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return ""


def parse_proc_stat(text: str) -> dict:
    cpus: dict[str, list[int]] = {}
    ctxt = procs_running = 0
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        key = parts[0]
        if key.startswith("cpu"):
            cpus[key] = [int(x) for x in parts[1:9]]  # user nice system idle iowait irq softirq steal
        elif key == "ctxt":
            ctxt = int(parts[1])
        elif key == "procs_running":
            procs_running = int(parts[1])
    return {"cpus": cpus, "ctxt": ctxt, "procs_running": procs_running}


def parse_pid_stat(text: str) -> dict | None:
    """utime+stime ticks, majflt, threads, rss pages from /proc/<pid>/stat."""
    close = text.rfind(")")
    if close < 0:
        return None
    fields = text[close + 2:].split()
    # fields[0] is state (field 3); majflt=12, utime=14, stime=15, threads=20, rss=24 (1-based)
    return {"majflt": int(fields[9]), "ticks": int(fields[11]) + int(fields[12]),
            "threads": int(fields[17]), "rss_pages": int(fields[21])}


def parse_sockstat(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if line.startswith("TCP:"):
            parts = line.split()[1:]
            out = {parts[i]: int(parts[i + 1]) for i in range(0, len(parts) - 1, 2)}
    return out


#: Cumulative kernel counters that are direct evidence of the connection path refusing work:
#: an accept queue overflowing, a SYN dropped at listen, the TIME_WAIT table full. A TIME_WAIT
#: COUNT is not such evidence — on loopback the server's own TIME_WAIT sockets hold no
#: ephemeral port — so it is recorded but never decides.
NETSTAT_KEYS = ("ListenOverflows", "ListenDrops", "TCPTimeWaitOverflow", "TCPAbortOnMemory")


def parse_netstat(text: str) -> dict[str, int]:
    lines = text.splitlines()
    out: dict[str, int] = {}
    for head, values in zip(lines[::2], lines[1::2]):
        if head.startswith("TcpExt:") and values.startswith("TcpExt:"):
            pairs = dict(zip(head.split()[1:], values.split()[1:]))
            out = {k: int(pairs[k]) for k in NETSTAT_KEYS if k in pairs}
    return out


def last_cpu(stat_text: str) -> int | None:
    """The CPU a task last ran on: field 39 (`processor`) of /proc/<pid>/task/<tid>/stat."""
    close = stat_text.rfind(")")
    fields = stat_text[close + 2:].split() if close >= 0 else []
    return int(fields[36]) if len(fields) > 36 else None


def _consumed_cpu_since(before: tuple | None, now: tuple) -> bool:
    """Whether the same watched group's thread used CPU time between the two samples."""
    return before is not None and before[0] == now[0] and now[1] > before[1]


def active_cpu(before: tuple | None, now: tuple) -> int | None:
    """The CPU a watched thread ran on in the last interval, or None if it did not run.

    `processor` is where a task LAST ran: a thread that has slept since it was moved keeps the
    CPU it ran on before, so reading it unconditionally reports a placement the scheduler can
    no longer produce. It counts only when the thread consumed CPU time since the previous
    sample (`now`/`before` are `(group, cpu ns, run-queue delay ns, processor)`)."""
    return now[3] if _consumed_cpu_since(before, now) else None


def parse_schedstat(text: str) -> tuple[int, int] | None:
    """(cpu ns, run-queue delay ns) from one /proc/<pid>/task/<tid>/schedstat."""
    fields = text.split()
    if len(fields) < 2:
        return None
    return int(fields[0]), int(fields[1])


def watch_group(category: str, thread_comm: str, pid: int, redis_roles: dict[int, str]) -> str | None:
    """The schedstat group a thread belongs to, or None when it is not watched."""
    if category == "proxy":
        if thread_comm.startswith("mcp-re-control"):
            return "proxy:control"
        return "proxy:serve" if thread_comm.startswith("mcp-re-serve") else "proxy:other"
    if category == "redis":
        return f"redis:{redis_roles.get(pid, 'other')}"
    return None


def cpu_busy(prev: list[int], cur: list[int]) -> tuple[float, float, float]:
    """(busy fraction, steal fraction, iowait fraction) between two /proc/stat cpu rows."""
    delta = [c - p for p, c in zip(prev, cur)]
    total = sum(delta) or 1
    idle = delta[3] + delta[4]
    return (total - idle) / total, delta[7] / total, delta[4] / total
