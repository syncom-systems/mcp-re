# SPDX-License-Identifier: Apache-2.0
"""One summary row per measured point: Phase A repetitions, Phase B attempts."""

from __future__ import annotations

from analysis_attribution import PointSetting, classify
from analysis_rules import RULES, median


def _latency_medians(valid: list[dict]) -> dict:
    return {
        "p50_us_median": median([r["p50_us"] for r in valid]),
        "p99_us_median": median([r["p99_us"] for r in valid]),
        "p999_us_median": median([r["p999_us"] for r in valid]),
        "p99_us_max": max((r["p99_us"] for r in valid), default=None),
    }


def phase_a_row(p: dict, vcpus: int) -> dict:
    valid = [r for r in p["reps"] if r["valid"]]
    tput = [r["throughput_rps"] for r in valid]
    setting = PointSetting(cores=p["cores"], workers=p["workers_per_shard"], vcpus=vcpus,
                           verdict=None, client_categories=("bench",), backend_budget=None)
    return {
        "cores": p["cores"], "workers_per_shard": p["workers_per_shard"], "status": p["status"],
        "reps_valid": len(valid), "reps_total": len(p["reps"]),
        "throughput_reps": tput, "throughput_median": median(tput), "throughput_min": min(tput, default=0.0),
        **_latency_medians(valid),
        "successes": sum(r["successes"] for r in valid), "failures": sum(r["failures"] for r in valid),
        "attribution": classify(p.get("telemetry", {}), setting),
    }


def _is_stable(proxy_rps: list[float], med: float) -> bool:
    return bool(proxy_rps) and (max(proxy_rps) - min(proxy_rps)) / med <= 0.10 if med else False


def _rung_rates(finals: list[dict]) -> tuple[list[float], list[float]]:
    """(the PROXY-verdict rates, every rate that counts as a measurement)."""
    proxy_rps = [f["row"]["rps"] for f in finals if f["verdict"] == "PROXY"]
    # An INVALID rung measured nothing; its number is never a best, a median or a curve point.
    all_rps = [f["row"]["rps"] for f in finals if f["verdict"] in {"PROXY", "CLIENT"}]
    return proxy_rps, all_rps


def _rung_setting(last: dict, cores: int, vcpus: int) -> PointSetting:
    return PointSetting(cores=cores, workers=last["workers_per_shard"], vcpus=vcpus,
                        verdict=(last.get("final") or {}).get("verdict"),
                        client_categories=("loadgen", "rig"),
                        backend_budget=RULES["rig_backend_workers"])


def phase_b_row(attempts: list[dict], cores: int, vcpus: int) -> dict:
    finals = [a["final"] for a in attempts if a.get("final")]
    proxy_rps, all_rps = _rung_rates(finals)
    med = median(proxy_rps)
    last = attempts[-1]
    last_final = last.get("final") or {}
    final_proxy = last_final.get("proxy") or {}
    return {
        "cores": cores, "attempts": len(attempts), "verdicts": [f["verdict"] for f in finals],
        "rps_attempts": all_rps, "rps_proxy_median": med if proxy_rps else None,
        "rps_best": max(all_rps, default=0.0),
        "stable": _is_stable(proxy_rps, med),
        "top_rung_connections": last_final.get("connections_per_generator"),
        "replay_pool_stated": sorted(set(final_proxy.get("replay_pool", []))),
        "redis_queue": last.get("redis_queue_final_rung") or {"available": False},
        "attribution": classify(last.get("telemetry_final_rung") or last.get("telemetry", {}),
                                _rung_setting(last, cores, vcpus)),
    }
