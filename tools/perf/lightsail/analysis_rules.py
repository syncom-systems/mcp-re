# SPDX-License-Identifier: Apache-2.0
"""The predeclared rule set, and how a (cores, throughput) curve is described under it."""

from __future__ import annotations

import statistics

RULES = {
    "knee": "first N in the sweep whose incremental efficiency (T(N)-T(prev)) / (T(prev) * (N/prev - 1)) < 0.5",
    "plateau": "T(N) <= 1.05 * T(prev) for the scaling sweep",
    "invalid_rung": "INVALID, never PROXY or CLIENT, when the rig log has any generator error, the row counts any "
                    "failure, or the replay store's SET count over the rung differs from what the rig's steps sent",
    "ceiling_reached": "two consecutive plateau points at the top of the sweep, each PROXY-verdict and stable",
    "stable": "(max - min) / median <= 0.10 across the attempts at one point",
    "still_scaling_at_top": "incremental efficiency between the last two sweep points >= 0.5",
    "steal_significant": 0.05,
    "host_exhausted_busy": 0.90,
    "component_saturated_fraction": 0.85,
    "proxy_underused_fraction": 0.60,
    "redis_primary_saturated_cores": 0.85,
    "connection_path_refusals": "any increase of ListenOverflows, ListenDrops, TCPTimeWaitOverflow or TCPAbortOnMemory",
    "hot_thread_cores": 0.85,
    "rig_backend_workers": 6,
    "rig_saturation_pct": 5.0,
}


def median(xs: list[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def incremental_efficiency(t_prev: float, t_cur: float, n_prev: int, n_cur: int) -> float | None:
    if t_prev <= 0 or n_cur <= n_prev:
        return None
    return (t_cur - t_prev) / (t_prev * (n_cur / n_prev - 1))


def _curve_row(n: int, t: float, base: float | None) -> dict:
    return {"cores": n, "throughput": t,
            "efficiency_vs_1": (t / (base * n)) if base else None, "incremental_efficiency": None,
            "plateau": False}


def _is_knee(incremental: float | None) -> bool:
    return incremental is not None and incremental < 0.5


def _plateau_start(current: int | None, on_plateau: bool, previous_n: int) -> int | None:
    """Where the plateau that reaches this point began; None once the curve climbs again."""
    if not on_plateau:
        return None
    return previous_n if current is None else current


def describe_curve(points: list[tuple[int, float]]) -> dict:
    """Efficiency, incremental efficiency, knee and plateau for an ascending (N, T) curve."""
    points = sorted(points)
    rows, knee, plateau_from = [], None, None
    base = next((t for n, t in points if n == 1), None)
    for i, (n, t) in enumerate(points):
        row = _curve_row(n, t, base)
        if i > 0:
            n0, t0 = points[i - 1]
            row["incremental_efficiency"] = incremental_efficiency(t0, t, n0, n)
            if knee is None and _is_knee(row["incremental_efficiency"]):
                knee = n
            row["plateau"] = t <= 1.05 * t0
            plateau_from = _plateau_start(plateau_from, row["plateau"], n0)
        rows.append(row)
    top_inc = rows[-1]["incremental_efficiency"] if len(rows) > 1 else None
    return {"rows": rows, "knee": knee, "plateau_from": plateau_from,
            "still_scaling_at_top": top_inc is not None and top_inc >= 0.5,
            "highest": max((r["throughput"] for r in rows), default=0.0)}
