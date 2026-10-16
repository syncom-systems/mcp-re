# SPDX-License-Identifier: Apache-2.0
"""Low-overhead host and process telemetry around one measurement point.

Two layers, both cheap enough to run during every authoritative measurement:

  * the standard sysstat/iproute tools (`mpstat -P ALL`, `pidstat -u -r -w`, `vmstat`,
    `sar -n DEV,TCP,ETCP,SOCK`) at 1 s, written raw beside the point as evidence a reader
    can re-derive anything from;
  * a /proc sampler at 0.25 s (a canonical rep can last about a second) that attributes CPU to the tiers the attribution rules need —
    proxy, client (bench / rig / generators), backend, Redis — and records host busy, steal,
    context switches, run queue, TIME_WAIT and file descriptors. Its per-point summary is
    what `analysis.py` classifies;
  * in the same pass, per-thread schedstat (`/proc/<pid>/task/<tid>/schedstat`: CPU time and
    RUN-QUEUE DELAY, both in ns) for the groups a replay-tier question needs apart: the
    proxy's control runtime (`mcp-re-control`, which drives the Redis connections), its
    serving threads, its other threads, and each Redis process by role (primary, replica-1,
    replica-2). Run-queue delay is time a thread was runnable and not running — direct
    evidence of host scheduling, which CPU totals cannot show.

Heavy profiling (perf, flamegraphs) is NOT here: it belongs to the diagnostic pass, after the
authoritative numbers are written, because it moves them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

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

EXTERNAL = {
    "mpstat.txt": ["mpstat", "-P", "ALL", "1"],
    "pidstat.txt": ["pidstat", "-h", "-u", "-r", "-w", "-C", "mcp-re|mcp_re|tls_load|saturation|redis", "1"],
    "vmstat.txt": ["vmstat", "-t", "-w", "1"],
    "sar-net.txt": ["sar", "-n", "DEV,TCP,ETCP,SOCK", "1"],
}


def categorize(name: str) -> str:
    for category, prefixes in CATEGORIES:
        if any(name.startswith(p) for p in prefixes):
            return category
    return "other"


def _read(path: str) -> str:
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
        if parts and parts[0].startswith("cpu"):
            cpus[parts[0]] = [int(x) for x in parts[1:9]]  # user nice system idle iowait irq softirq steal
        elif parts and parts[0] == "ctxt":
            ctxt = int(parts[1])
        elif parts and parts[0] == "procs_running":
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


def _cpu_busy(prev: list[int], cur: list[int]) -> tuple[float, float, float]:
    """(busy fraction, steal fraction, iowait fraction) between two /proc/stat cpu rows."""
    delta = [c - p for p, c in zip(prev, cur)]
    total = sum(delta) or 1
    idle = delta[3] + delta[4]
    return (total - idle) / total, delta[7] / total, delta[4] / total


class Sampler(threading.Thread):
    def __init__(self, out: Path, period: float = 0.25, redis_roles: dict[int, str] | None = None):
        super().__init__(daemon=True)
        self.out, self.period = out, period
        self.redis_roles = redis_roles or {}
        self.stop_event = threading.Event()
        self.samples: list[dict] = []

    @staticmethod
    def _proxy_threads(procs: dict[int, tuple[str, dict]]) -> dict[tuple[int, int], int]:
        """CPU ticks per proxy THREAD: one saturated worker is invisible in a process total."""
        ticks = {}
        for pid, (name, _) in procs.items():
            if categorize(name) != "proxy":
                continue
            try:
                tids = os.listdir(f"/proc/{pid}/task")
            except OSError:
                continue
            for tid in tids:
                stat = parse_pid_stat(_read(f"/proc/{pid}/task/{tid}/stat"))
                if stat is not None:
                    ticks[(pid, int(tid))] = stat["ticks"]
        return ticks

    def _watched(self, procs: dict[int, tuple[str, dict]]) -> dict[tuple[int, int], tuple[str, int, int]]:
        """(group, cpu ns, run-queue delay ns) per watched thread."""
        out = {}
        for pid, (name, _) in procs.items():
            category = categorize(name)
            if category not in ("proxy", "redis"):
                continue
            try:
                tids = os.listdir(f"/proc/{pid}/task")
            except OSError:
                continue
            for tid in tids:
                group = watch_group(category, _read(f"/proc/{pid}/task/{tid}/comm").strip(), pid,
                                    self.redis_roles)
                stat = parse_schedstat(_read(f"/proc/{pid}/task/{tid}/schedstat"))
                if group is not None and stat is not None:
                    out[(pid, int(tid))] = (group, *stat)
        return out

    def _processes(self) -> dict[int, tuple[str, dict]]:
        found = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            comm = _read(f"/proc/{pid}/comm").strip()
            try:
                name = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
            except OSError:
                name = comm
            # The executable decides (comm is truncated to 15 characters); comm is the
            # fallback for an executable that names something else, e.g. a symlinked binary.
            if categorize(name) == "other" and categorize(comm) != "other":
                name = comm
            stat = parse_pid_stat(_read(f"/proc/{pid}/stat"))
            if stat is not None:
                found[pid] = (name, stat)
        return found

    def run(self) -> None:
        prev_stat = parse_proc_stat(_read("/proc/stat"))
        prev_procs = self._processes()
        prev_threads = self._proxy_threads(prev_procs)
        prev_watch = self._watched(prev_procs)
        prev_t = time.monotonic()
        with open(self.out, "w") as sink:
            while not self.stop_event.wait(self.period):
                now = time.monotonic()
                stat = parse_proc_stat(_read("/proc/stat"))
                procs = self._processes()
                threads = self._proxy_threads(procs)
                watch_now = self._watched(procs)
                dt = now - prev_t
                watch: dict[str, dict] = {}
                for key, (group, cpu_ns, delay_ns) in watch_now.items():
                    row = watch.setdefault(group, {"cores": 0.0, "run_delay": 0.0, "threads": 0})
                    row["threads"] += 1
                    before = prev_watch.get(key)
                    if before is not None and before[0] == group:
                        row["cores"] += (cpu_ns - before[1]) / 1e9 / dt
                        row["run_delay"] += (delay_ns - before[2]) / 1e9 / dt
                heat = [(threads[k] - prev_threads[k]) / CLK_TCK / dt for k in threads if k in prev_threads]
                per_cpu = {name: _cpu_busy(prev_stat["cpus"][name], row)
                           for name, row in stat["cpus"].items() if name in prev_stat["cpus"]}
                categories: dict[str, dict] = {}
                for pid, (name, cur) in procs.items():
                    cat = categorize(name)
                    agg = categories.setdefault(cat, {"cores": 0.0, "pid_max_cores": 0.0, "rss_bytes": 0,
                                                      "majflt": 0, "threads": 0, "pids": 0})
                    before = prev_procs.get(pid)
                    if before is not None and before[0] == name:
                        used = (cur["ticks"] - before[1]["ticks"]) / CLK_TCK / dt
                        agg["cores"] += used
                        agg["pid_max_cores"] = max(agg["pid_max_cores"], used)
                        agg["majflt"] += cur["majflt"] - before[1]["majflt"]
                    agg["rss_bytes"] += cur["rss_pages"] * PAGE
                    agg["threads"] += cur["threads"]
                    agg["pids"] += 1
                total = per_cpu.pop("cpu", (0.0, 0.0, 0.0))
                sample = {
                    "t": time.time(),
                    "host_busy": total[0], "steal": total[1], "iowait": total[2],
                    "max_cpu_busy": max((v[0] for v in per_cpu.values()), default=0.0),
                    "ctxt_per_s": (stat["ctxt"] - prev_stat["ctxt"]) / dt,
                    "procs_running": stat["procs_running"],
                    "loadavg1": float((_read("/proc/loadavg").split() or ["0"])[0]),
                    "tcp": parse_sockstat(_read("/proc/net/sockstat")),
                    "file_nr": int((_read("/proc/sys/fs/file-nr").split() or ["0"])[0]),
                    "netstat": parse_netstat(_read("/proc/net/netstat")),
                    "proxy_thread_max": max(heat, default=0.0),
                    "proxy_threads_hot": sum(1 for h in heat if h >= 0.85),
                    "categories": categories,
                    "watch": watch,
                }
                sink.write(json.dumps(sample) + "\n")
                sink.flush()
                self.samples.append(sample)
                prev_stat, prev_procs, prev_threads, prev_t = stat, procs, threads, now
                prev_watch = watch_now


def summarize(samples: list[dict], vcpus: int) -> dict:
    """Per-point averages and peaks from the sampler's records."""
    if not samples:
        return {"available": False, "reason": "no samples"}

    def avg(key: str) -> float:
        return sum(s[key] for s in samples) / len(samples)

    cats = sorted({c for s in samples for c in s["categories"]})
    per_cat = {}
    for cat in cats:
        rows = [s["categories"].get(cat, {}) for s in samples]
        cores = [r.get("cores", 0.0) for r in rows]
        per_cat[cat] = {
            "cores_avg": sum(cores) / len(cores),
            "cores_p90": sorted(cores)[int(0.9 * (len(cores) - 1))],
            "pid_max_cores_avg": sum(r.get("pid_max_cores", 0.0) for r in rows) / len(rows),
            "rss_max_bytes": max(r.get("rss_bytes", 0) for r in rows),
            "majflt_total": sum(r.get("majflt", 0) for r in rows),
            "threads_max": max(r.get("threads", 0) for r in rows),
        }
    return {
        "available": True,
        "samples": len(samples),
        "vcpus": vcpus,
        "host_busy_avg": avg("host_busy"),
        "steal_avg": avg("steal"),
        "steal_max": max(s["steal"] for s in samples),
        "iowait_avg": avg("iowait"),
        "max_cpu_busy_avg": avg("max_cpu_busy"),
        "ctxt_per_s_avg": avg("ctxt_per_s"),
        "procs_running_avg": avg("procs_running"),
        "procs_running_max": max(s["procs_running"] for s in samples),
        "loadavg1_max": max(s["loadavg1"] for s in samples),
        "tcp_tw_max": max(s["tcp"].get("tw", 0) for s in samples),
        "tcp_inuse_max": max(s["tcp"].get("inuse", 0) for s in samples),
        "tcp_orphan_max": max(s["tcp"].get("orphan", 0) for s in samples),
        "file_nr_max": max(s["file_nr"] for s in samples),
        "netstat_delta": {k: max(s["netstat"].get(k, 0) for s in samples) - min(s["netstat"].get(k, 0) for s in samples)
                          for k in NETSTAT_KEYS},
        "proxy_thread_max_avg": sum(s.get("proxy_thread_max", 0.0) for s in samples) / len(samples),
        "proxy_threads_hot_avg": sum(s.get("proxy_threads_hot", 0) for s in samples) / len(samples),
        "categories": per_cat,
        "watch": _watch_summary(samples),
    }


def _watch_summary(samples: list[dict]) -> dict:
    """Per schedstat group: mean cores, mean and peak run-queue delay (s per s, summed over
    the group's threads), and the thread count."""
    groups = sorted({g for s in samples for g in s.get("watch", {})})
    out = {}
    for group in groups:
        rows = [s.get("watch", {}).get(group, {}) for s in samples]
        out[group] = {"cores_avg": sum(r.get("cores", 0.0) for r in rows) / len(rows),
                      "run_delay_avg": sum(r.get("run_delay", 0.0) for r in rows) / len(rows),
                      "run_delay_max": max(r.get("run_delay", 0.0) for r in rows),
                      "threads_max": max(r.get("threads", 0) for r in rows)}
    return out


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

    def __enter__(self) -> "Telemetry":
        self.dir.mkdir(parents=True, exist_ok=True)
        linux = os.path.isdir("/proc/self")
        missing = [argv[0] for argv in EXTERNAL.values() if shutil.which(argv[0]) is None]
        if self.require and (not linux or missing):
            raise RuntimeError(f"telemetry required but unavailable (linux={linux}, missing={missing})")
        if not linux:
            self.result = {"available": False, "reason": "no /proc on this host (not Linux)"}
            return self
        _snapshot(self.dir / "before.json")
        for name, argv in EXTERNAL.items():
            if shutil.which(argv[0]):
                handle = open(self.dir / name, "w")
                self.external.append(subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                                                      env=dict(os.environ, LC_ALL="C", S_TIME_FORMAT="ISO")))
        self.sampler = Sampler(self.dir / "proc-samples.jsonl", redis_roles=self.redis_roles)
        self.sampler.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.sampler is not None:
            self.sampler.stop_event.set()
            self.sampler.join(timeout=10)
            self.result = summarize(self.sampler.samples, self.vcpus)
        for proc in self.external:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.isdir("/proc/self"):
            _snapshot(self.dir / "after.json")
        (self.dir / "summary.json").write_text(json.dumps(self.result, indent=2, sort_keys=True) + "\n")
