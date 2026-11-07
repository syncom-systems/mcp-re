# SPDX-License-Identifier: Apache-2.0
"""Summaries per process category and per schedstat group."""

from __future__ import annotations


def mean(rows: list[dict], key: str, default: float = 0.0) -> float:
    return sum(r.get(key, default) for r in rows) / len(rows)


def maximum(rows: list[dict], key: str, default: float = 0.0) -> float:
    return max(r.get(key, default) for r in rows)


def category_summary(samples: list[dict]) -> dict:
    out = {}
    for cat in sorted({c for s in samples for c in s["categories"]}):
        rows = [s["categories"].get(cat, {}) for s in samples]
        cores = [r.get("cores", 0.0) for r in rows]
        out[cat] = {
            "cores_avg": sum(cores) / len(cores),
            "cores_p90": sorted(cores)[int(0.9 * (len(cores) - 1))],
            "pid_max_cores_avg": mean(rows, "pid_max_cores"),
            "rss_max_bytes": maximum(rows, "rss_bytes", 0),
            "majflt_total": sum(r.get("majflt", 0) for r in rows),
            "threads_max": maximum(rows, "threads", 0),
        }
    return out


def watch_summary(samples: list[dict]) -> dict:
    """Per schedstat group: mean cores, mean and peak run-queue delay (s per s, summed over
    the group's threads), and the thread count."""
    out = {}
    for group in sorted({g for s in samples for g in s.get("watch", {})}):
        rows = [s.get("watch", {}).get(group, {}) for s in samples]
        out[group] = {"cores_avg": mean(rows, "cores"),
                      "run_delay_avg": mean(rows, "run_delay"),
                      "run_delay_max": maximum(rows, "run_delay"),
                      "threads_max": maximum(rows, "threads", 0),
                      "cpus_seen": sorted({c for r in rows for c in r.get("cpus", [])})}
    return out
