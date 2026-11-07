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
    evidence of host scheduling, which CPU totals cannot show. The CPUs a group ran on count a
    thread only in a sample in which it consumed CPU time (`active_cpu`).

Heavy profiling (perf, flamegraphs) is NOT here: it belongs to the diagnostic pass, after the
authoritative numbers are written, because it moves them.

The parts live beside this file: `telemetry_proc` (parsers and process categories),
`telemetry_sampler` (the /proc sampler), `telemetry_summary` and `telemetry_groups` (per-point averages) and
`telemetry_collect` (the context manager and the sysstat collectors).
"""

from __future__ import annotations

from telemetry_collect import EXTERNAL, Telemetry
from telemetry_proc import (
    CATEGORIES,
    CLK_TCK,
    NETSTAT_KEYS,
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
    watch_group,
)
from telemetry_sampler import Sampler
from telemetry_summary import summarize

__all__ = [
    "CATEGORIES", "CLK_TCK", "EXTERNAL", "NETSTAT_KEYS", "PAGE", "Sampler", "Telemetry",
    "active_cpu", "categorize", "cpu_busy", "last_cpu", "parse_netstat", "parse_pid_stat",
    "parse_proc_stat", "parse_schedstat", "parse_sockstat", "summarize", "watch_group",
]
