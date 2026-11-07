# SPDX-License-Identifier: Apache-2.0
"""Per-point averages and peaks from the sampler's records."""

from __future__ import annotations

from telemetry_groups import category_summary, mean, watch_summary
from telemetry_proc import NETSTAT_KEYS


def _netstat_delta(samples: list[dict]) -> dict:
    return {k: max(s["netstat"].get(k, 0) for s in samples) - min(s["netstat"].get(k, 0) for s in samples)
            for k in NETSTAT_KEYS}


def _peaks(samples: list[dict]) -> dict:
    """The highest value any sample saw of each gauge."""
    return {
        "steal_max": max(s["steal"] for s in samples),
        "procs_running_max": max(s["procs_running"] for s in samples),
        "loadavg1_max": max(s["loadavg1"] for s in samples),
        "tcp_tw_max": max(s["tcp"].get("tw", 0) for s in samples),
        "tcp_inuse_max": max(s["tcp"].get("inuse", 0) for s in samples),
        "tcp_orphan_max": max(s["tcp"].get("orphan", 0) for s in samples),
        "file_nr_max": max(s["file_nr"] for s in samples),
    }


def summarize(samples: list[dict], vcpus: int) -> dict:
    """Per-point averages and peaks from the sampler's records."""
    if not samples:
        return {"available": False, "reason": "no samples"}

    peaks = _peaks(samples)
    return {
        "available": True,
        "samples": len(samples),
        "vcpus": vcpus,
        "host_busy_avg": mean(samples, "host_busy"),
        "steal_avg": mean(samples, "steal"),
        "steal_max": peaks["steal_max"],
        "iowait_avg": mean(samples, "iowait"),
        "max_cpu_busy_avg": mean(samples, "max_cpu_busy"),
        "ctxt_per_s_avg": mean(samples, "ctxt_per_s"),
        "procs_running_avg": mean(samples, "procs_running"),
        "procs_running_max": peaks["procs_running_max"],
        "loadavg1_max": peaks["loadavg1_max"],
        "tcp_tw_max": peaks["tcp_tw_max"],
        "tcp_inuse_max": peaks["tcp_inuse_max"],
        "tcp_orphan_max": peaks["tcp_orphan_max"],
        "file_nr_max": peaks["file_nr_max"],
        "netstat_delta": _netstat_delta(samples),
        "proxy_thread_max_avg": mean(samples, "proxy_thread_max"),
        "proxy_threads_hot_avg": mean(samples, "proxy_threads_hot"),
        "categories": category_summary(samples),
        "watch": watch_summary(samples),
    }
