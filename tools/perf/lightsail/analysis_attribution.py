# SPDX-License-Identifier: Apache-2.0
"""Which component the host evidence points at: an ordered list of predeclared rules."""

from __future__ import annotations

from dataclasses import dataclass

from analysis_rules import RULES


@dataclass(frozen=True)
class PointSetting:
    """What was configured at a measured point, as opposed to what was observed there.

    `verdict` is the instrument's own (rig PROXY/CLIENT/INVALID; None for Phase A). The
    proxy's budget is its serving threads: N under the scaling topology (one worker per
    shard), the whole host under the shipped auto topology (cores=0).
    """

    cores: int
    workers: int
    vcpus: int
    verdict: str | None
    client_categories: tuple[str, ...]
    backend_budget: float | None


@dataclass(frozen=True)
class Reading:
    """The telemetry of one point, reduced to the quantities the rules compare."""

    proxy: float
    client: float
    backend: float
    redis_primary: float
    busy: float
    steal: float
    budget: float
    serving: float
    refusals: dict
    hot: float
    thread_max: float
    evidence: dict


def _cores_of(cats: dict, *names: str) -> float:
    return sum(cats.get(n, {}).get("cores_avg", 0.0) for n in names)


def _budget(setting: PointSetting) -> float:
    budget = float(setting.vcpus if setting.cores == 0 else setting.cores * max(setting.workers, 1))
    return min(budget, float(setting.vcpus))


def _evidence(telemetry: dict, setting: PointSetting, measured: dict) -> dict:
    return {"proxy_cores": round(measured["proxy"], 2), "proxy_budget": measured["budget"],
            "client_cores": round(measured["client"], 2),
            "backend_cores": round(measured["backend"], 2),
            "redis_primary_cores": round(measured["redis_primary"], 2),
            "host_busy": round(measured["busy"], 3), "steal": round(measured["steal"], 4),
            "max_cpu_busy": round(telemetry.get("max_cpu_busy_avg", 0.0), 3),
            "ctxt_per_s": round(telemetry.get("ctxt_per_s_avg", 0.0)),
            "procs_running_avg": round(telemetry.get("procs_running_avg", 0.0), 1),
            "tcp_tw_max": telemetry.get("tcp_tw_max"),
            "connection_refusals": measured["refusals"],
            "proxy_thread_max": round(measured["thread_max"], 2),
            "proxy_threads_hot": round(measured["hot"], 1), "verdict": setting.verdict}


def read_telemetry(telemetry: dict, setting: PointSetting) -> Reading:
    cats = telemetry.get("categories", {})
    budget = _budget(setting)
    measured = {
        "proxy": _cores_of(cats, "proxy"),
        "client": _cores_of(cats, *setting.client_categories),
        "backend": _cores_of(cats, "backend"),
        "redis_primary": cats.get("redis", {}).get("pid_max_cores_avg", 0.0),
        "busy": telemetry.get("host_busy_avg", 0.0),
        "steal": telemetry.get("steal_avg", 0.0),
        "budget": budget,
        "refusals": {k: v for k, v in (telemetry.get("netstat_delta") or {}).items() if v > 0},
        "hot": telemetry.get("proxy_threads_hot_avg", 0.0),
        "thread_max": telemetry.get("proxy_thread_max_avg", 0.0),
    }
    serving = budget if setting.cores == 0 else float(
        min(setting.cores * max(setting.workers, 1), setting.vcpus))
    return Reading(serving=serving, evidence=_evidence(telemetry, setting, measured), **measured)


def _outcome(label: str, confidence: str, why: str) -> tuple[str, str, str]:
    return label, confidence, why


def _host_scheduling(r: Reading, s: PointSetting):
    if r.steal >= RULES["steal_significant"]:
        return _outcome("HOST_SCHEDULING", "medium", f"steal {r.steal:.1%} >= {RULES['steal_significant']:.0%}: the VM "
                        "was not given the CPU it was scheduled for; a Lightsail/host limitation until proven otherwise")
    return None


def _replay_tier(r: Reading, s: PointSetting):
    if r.redis_primary >= RULES["redis_primary_saturated_cores"]:
        return _outcome("REPLAY_TIER", "medium", f"the Redis primary used {r.redis_primary:.2f} of its one core")
    return None


def _backend(r: Reading, s: PointSetting):
    sat = RULES["component_saturated_fraction"]
    if s.backend_budget and r.backend >= sat * s.backend_budget:
        return _outcome("BACKEND", "medium", f"the backend used {r.backend:.2f} of its {s.backend_budget} worker cores")
    return None


def _connection_path(r: Reading, s: PointSetting):
    if r.refusals:
        return _outcome("OS_CONNECTION_PATH", "medium",
                        f"the kernel refused connection work during the window: {r.refusals}")
    return None


def _client_verdict(r: Reading, s: PointSetting):
    if s.verdict != "CLIENT":
        return None
    if r.busy >= RULES["host_exhausted_busy"]:
        return _outcome("INDETERMINATE", "high", f"still client-limited at the top of the ladder with the host "
                        f"{r.busy:.0%} busy: no spare CPU exists to separate proxy capacity from generator contention")
    return _outcome("CLIENT_LIMITED", "high", "the rig still gained >5% from one more generator at the top rung; "
                    "the row is a floor, not the proxy's ceiling")


def _proxy_saturated(r: Reading, s: PointSetting) -> bool:
    sat = RULES["component_saturated_fraction"]
    return r.proxy >= sat * r.budget or (s.cores > 0 and r.hot >= sat * r.serving)


def _proxy_cpu(r: Reading, s: PointSetting):
    if not _proxy_saturated(r, s):
        return None
    confident = r.busy < RULES["host_exhausted_busy"] or s.cores == s.vcpus
    return _outcome("PROXY_CPU", "high" if confident else "medium",
                    f"the proxy used {r.proxy:.1f} of its {r.budget:.0f}-core budget")


def _host_exhausted(r: Reading, s: PointSetting):
    if r.busy >= RULES["host_exhausted_busy"]:
        return _outcome("INDETERMINATE", "medium", f"the host was {r.busy:.0%} busy while the proxy used only "
                        f"{r.proxy:.1f} of {r.budget:.0f} cores: co-located load competed for the CPU the proxy was given")
    return None


def _client_took_the_cpu(r: Reading, s: PointSetting):
    sat = RULES["component_saturated_fraction"]
    if s.verdict is None and r.client >= sat * max(s.vcpus - r.proxy, 1.0):
        return _outcome("CLIENT_LIMITED", "medium", "the canonical client consumed the CPU the proxy did not")
    return None


def _threads_serialized(r: Reading) -> bool:
    """One thread near a full core while under half the serving threads are hot."""
    return r.thread_max >= RULES["hot_thread_cores"] and r.hot < 0.5 * r.serving


def _one_hot_thread(r: Reading, s: PointSetting):
    if r.serving > 1 and _threads_serialized(r):
        return _outcome("PROXY_SERIALIZATION_OR_CONTENTION", "medium",
                        f"one proxy thread ran at {r.thread_max:.2f} core while "
                        f"only {r.hot:.1f} of {r.serving:.0f} serving threads were hot: a serialized path")
    return None


def _proxy_underused(r: Reading, s: PointSetting):
    if r.proxy <= RULES["proxy_underused_fraction"] * r.budget:
        return _outcome("PROXY_SERIALIZATION_OR_CONTENTION", "low",
                        f"throughput stopped with the proxy at {r.proxy:.1f} of "
                        f"{r.budget:.0f} cores and the host not exhausted: look for a serialized path, lock or futex "
                        "contention — the diagnostic pass decides")
    return None


#: In the order they are tried; the first to fire decides.
RULE_ORDER = (_host_scheduling, _replay_tier, _backend, _connection_path, _client_verdict,
              _proxy_cpu, _host_exhausted, _client_took_the_cpu, _one_hot_thread, _proxy_underused)


def classify(telemetry: dict, setting: PointSetting) -> dict:
    """Which component the host evidence points at, with the evidence and a confidence."""
    if setting.verdict == "INVALID":
        return {"label": "INVALID", "confidence": "high",
                "why": "the rung is not evidence: a step hit errors or failures, or the replay store did not see "
                       "every request the rig's steps sent"}
    if not telemetry or not telemetry.get("available"):
        return {"label": "UNATTRIBUTED", "confidence": "none", "why": "no telemetry for this point"}
    reading = read_telemetry(telemetry, setting)
    for rule in RULE_ORDER:
        fired = rule(reading, setting)
        if fired is not None:
            label, confidence, why = fired
            return {"label": label, "confidence": confidence, "why": why, "evidence": reading.evidence}
    return {"label": "UNEXPLAINED", "confidence": "low",
            "why": "no rule fired: run the diagnostic profiling pass on this configuration",
            "evidence": reading.evidence}
