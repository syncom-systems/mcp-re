# SPDX-License-Identifier: Apache-2.0
"""The /proc sampler: CPU by tier, per-thread schedstat groups, host busy, steal, sockets."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from telemetry_proc import (
    CLK_TCK,
    PAGE,
    active_cpu,
    categorize,
    cpu_busy,
    last_cpu,
    parse_netstat,
    parse_pid_stat,
    parse_proc_stat,
    parse_schedstat,
    parse_sockstat,
    read_text,
    watch_group,
)

Procs = dict[int, tuple[str, dict]]
Watched = dict[tuple[int, int], tuple[str, int, int, int | None]]


@dataclass(frozen=True)
class Reading:
    """Everything /proc said at one instant; `t` is the monotonic time the caller assigns it."""

    stat: dict
    procs: Procs
    threads: dict[tuple[int, int], int]
    watch: Watched
    t: float = 0.0


def _task_ids(procs: Procs, categories: tuple[str, ...]):
    """`(pid, category, tid)` for every thread of every process in `categories`."""
    for pid, (name, _) in procs.items():
        category = categorize(name)
        if category not in categories:
            continue
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for tid in tids:
            yield pid, category, tid


def _processes() -> Procs:
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        comm = read_text(f"/proc/{pid}/comm").strip()
        try:
            name = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
        except OSError:
            name = comm
        # The executable decides (comm is truncated to 15 characters); comm is the
        # fallback for an executable that names something else, e.g. a symlinked binary.
        if categorize(name) == "other" and categorize(comm) != "other":
            name = comm
        stat = parse_pid_stat(read_text(f"/proc/{pid}/stat"))
        if stat is not None:
            found[pid] = (name, stat)
    return found


def _proxy_threads(procs: Procs) -> dict[tuple[int, int], int]:
    """CPU ticks per proxy THREAD: one saturated worker is invisible in a process total."""
    ticks = {}
    for pid, _, tid in _task_ids(procs, ("proxy",)):
        stat = parse_pid_stat(read_text(f"/proc/{pid}/task/{tid}/stat"))
        if stat is not None:
            ticks[(pid, int(tid))] = stat["ticks"]
    return ticks


def _watched(procs: Procs, redis_roles: dict[int, str]) -> Watched:
    """(group, cpu ns, run-queue delay ns, CPU last run on) per watched thread."""
    out = {}
    for pid, category, tid in _task_ids(procs, ("proxy", "redis")):
        group = watch_group(category, read_text(f"/proc/{pid}/task/{tid}/comm").strip(), pid, redis_roles)
        stat = parse_schedstat(read_text(f"/proc/{pid}/task/{tid}/schedstat"))
        if group is not None and stat is not None:
            out[(pid, int(tid))] = (group, *stat, last_cpu(read_text(f"/proc/{pid}/task/{tid}/stat")))
    return out


def read_proc(redis_roles: dict[int, str]) -> Reading:
    stat = parse_proc_stat(read_text("/proc/stat"))
    procs = _processes()
    return Reading(stat, procs, _proxy_threads(procs), _watched(procs, redis_roles))


def _watch_rows(prev: Reading, cur: Reading, dt: float) -> dict[str, dict]:
    """Per schedstat group: cores, run-queue delay, thread count and the CPUs it ran on."""
    watch: dict[str, dict] = {}
    for key, (group, cpu_ns, delay_ns, _ran_on) in cur.watch.items():
        row = watch.setdefault(group, {"cores": 0.0, "run_delay": 0.0, "threads": 0, "cpus": []})
        row["threads"] += 1
        before = prev.watch.get(key)
        ran_on = active_cpu(before, cur.watch[key])
        if ran_on is not None and ran_on not in row["cpus"]:
            row["cpus"].append(ran_on)
        if before is not None and before[0] == group:
            row["cores"] += (cpu_ns - before[1]) / 1e9 / dt
            row["run_delay"] += (delay_ns - before[2]) / 1e9 / dt
    return watch


def _category_rows(prev: Reading, cur: Reading, dt: float) -> dict[str, dict]:
    """Per process category: cores used, busiest pid, memory, faults, threads and pids."""
    categories: dict[str, dict] = {}
    for pid, (name, now) in cur.procs.items():
        agg = categories.setdefault(categorize(name), {"cores": 0.0, "pid_max_cores": 0.0, "rss_bytes": 0,
                                                       "majflt": 0, "threads": 0, "pids": 0})
        before = prev.procs.get(pid)
        if before is not None and before[0] == name:
            used = (now["ticks"] - before[1]["ticks"]) / CLK_TCK / dt
            agg["cores"] += used
            agg["pid_max_cores"] = max(agg["pid_max_cores"], used)
            agg["majflt"] += now["majflt"] - before[1]["majflt"]
        agg["rss_bytes"] += now["rss_pages"] * PAGE
        agg["threads"] += now["threads"]
        agg["pids"] += 1
    return categories


def _per_cpu(prev: Reading, cur: Reading) -> dict[str, tuple[float, float, float]]:
    return {name: cpu_busy(prev.stat["cpus"][name], row)
            for name, row in cur.stat["cpus"].items() if name in prev.stat["cpus"]}


def sample(prev: Reading, cur: Reading) -> dict:
    """One sample record: what the host and the watched processes did between two readings."""
    dt = cur.t - prev.t
    heat = [(cur.threads[k] - prev.threads[k]) / CLK_TCK / dt for k in cur.threads if k in prev.threads]
    per_cpu = _per_cpu(prev, cur)
    total = per_cpu.pop("cpu", (0.0, 0.0, 0.0))
    return {
        "t": time.time(),
        "host_busy": total[0], "steal": total[1], "iowait": total[2],
        "max_cpu_busy": max((v[0] for v in per_cpu.values()), default=0.0),
        "ctxt_per_s": (cur.stat["ctxt"] - prev.stat["ctxt"]) / dt,
        "procs_running": cur.stat["procs_running"],
        "loadavg1": float((read_text("/proc/loadavg").split() or ["0"])[0]),
        "tcp": parse_sockstat(read_text("/proc/net/sockstat")),
        "file_nr": int((read_text("/proc/sys/fs/file-nr").split() or ["0"])[0]),
        "netstat": parse_netstat(read_text("/proc/net/netstat")),
        "proxy_thread_max": max(heat, default=0.0),
        "proxy_threads_hot": sum(1 for h in heat if h >= 0.85),
        "categories": _category_rows(prev, cur, dt),
        "watch": _watch_rows(prev, cur, dt),
        "cpu_busy": {name[3:]: round(v[0], 3) for name, v in per_cpu.items()},
    }


class Sampler(threading.Thread):
    def __init__(self, out: Path, period: float = 0.25, redis_roles: dict[int, str] | None = None):
        super().__init__(daemon=True)
        self.out, self.period = out, period
        self.redis_roles = redis_roles or {}
        self.stop_event = threading.Event()
        self.samples: list[dict] = []

    def run(self) -> None:
        # The first reading is stamped after it is taken, every later one before: the interval
        # between two stamps is then the sleep between the readings, not the time spent reading.
        prev = replace(read_proc(self.redis_roles), t=time.monotonic())
        with open(self.out, "w") as sink:
            while not self.stop_event.wait(self.period):
                now = time.monotonic()
                cur = replace(read_proc(self.redis_roles), t=now)
                record = sample(prev, cur)
                sink.write(json.dumps(record) + "\n")
                sink.flush()
                self.samples.append(record)
                prev = cur
