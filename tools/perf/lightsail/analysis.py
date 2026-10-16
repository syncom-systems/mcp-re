# SPDX-License-Identifier: Apache-2.0
"""Aggregation, the predeclared knee/plateau rules, and bottleneck attribution.

EVERY THRESHOLD BELOW IS DECLARED BEFORE THE RUN. They are recorded in the run manifest
(`RULES`) and in docs/bench/lightsail-ceiling-runbook.md, and a summary states the rule set
it was produced under. None of them is a pass/fail threshold for MCP-RE: this experiment
characterizes a new hardware context and has no predeclared floor. They decide only how a
curve is DESCRIBED (where its knee is, whether it has plateaued) and which component the
host evidence points at when it does.

The two curves are never merged: Phase A is the canonical security-path curve measured by a
client that signs on its own hot path; Phase B is the proxy-ceiling curve measured by the
saturation rig. A Phase A plateau that Phase B does not share is a CLIENT plateau.
"""

from __future__ import annotations

import statistics
from pathlib import Path

from common import read_json

RULES = {
    "knee": "first N in the sweep whose incremental efficiency (T(N)-T(prev)) / (T(prev) * (N/prev - 1)) < 0.5",
    "plateau": "T(N) <= 1.05 * T(prev) for the scaling sweep",
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


def describe_curve(points: list[tuple[int, float]]) -> dict:
    """Efficiency, incremental efficiency, knee and plateau for an ascending (N, T) curve."""
    points = sorted(points)
    rows, knee, plateau_from = [], None, None
    base = next((t for n, t in points if n == 1), None)
    for i, (n, t) in enumerate(points):
        row = {"cores": n, "throughput": t,
               "efficiency_vs_1": (t / (base * n)) if base else None, "incremental_efficiency": None,
               "plateau": False}
        if i > 0:
            n0, t0 = points[i - 1]
            inc = incremental_efficiency(t0, t, n0, n)
            row["incremental_efficiency"] = inc
            if knee is None and inc is not None and inc < 0.5:
                knee = n
            row["plateau"] = t <= 1.05 * t0
            if row["plateau"] and plateau_from is None:
                plateau_from = n0
            if not row["plateau"]:
                plateau_from = None
        rows.append(row)
    top_inc = rows[-1]["incremental_efficiency"] if len(rows) > 1 else None
    return {"rows": rows, "knee": knee, "plateau_from": plateau_from,
            "still_scaling_at_top": top_inc is not None and top_inc >= 0.5,
            "highest": max((r["throughput"] for r in rows), default=0.0)}


def classify(telemetry: dict, *, cores: int, workers: int, vcpus: int, verdict: str | None,
             client_categories: tuple[str, ...], backend_budget: float | None) -> dict:
    """Which component the host evidence points at, with the evidence and a confidence.

    `verdict` is the instrument's own (rig PROXY/CLIENT/INVALID; None for Phase A).
    The proxy's budget is its serving threads: N under the scaling topology (one worker per
    shard), the whole host under the shipped auto topology (cores=0)."""
    if not telemetry or not telemetry.get("available"):
        return {"label": "UNATTRIBUTED", "confidence": "none", "why": "no telemetry for this point"}
    cats = telemetry.get("categories", {})

    def cores_of(*names: str) -> float:
        return sum(cats.get(n, {}).get("cores_avg", 0.0) for n in names)

    proxy = cores_of("proxy")
    client = cores_of(*client_categories)
    backend = cores_of("backend")
    redis_primary = cats.get("redis", {}).get("pid_max_cores_avg", 0.0)
    busy, steal = telemetry.get("host_busy_avg", 0.0), telemetry.get("steal_avg", 0.0)
    budget = float(vcpus if cores == 0 else cores * max(workers, 1))
    budget = min(budget, float(vcpus))
    refusals = {k: v for k, v in (telemetry.get("netstat_delta") or {}).items() if v > 0}
    hot = telemetry.get("proxy_threads_hot_avg", 0.0)
    thread_max = telemetry.get("proxy_thread_max_avg", 0.0)
    evidence = {"proxy_cores": round(proxy, 2), "proxy_budget": budget, "client_cores": round(client, 2),
                "backend_cores": round(backend, 2), "redis_primary_cores": round(redis_primary, 2),
                "host_busy": round(busy, 3), "steal": round(steal, 4),
                "max_cpu_busy": round(telemetry.get("max_cpu_busy_avg", 0.0), 3),
                "ctxt_per_s": round(telemetry.get("ctxt_per_s_avg", 0.0)),
                "procs_running_avg": round(telemetry.get("procs_running_avg", 0.0), 1),
                "tcp_tw_max": telemetry.get("tcp_tw_max"), "connection_refusals": refusals,
                "proxy_thread_max": round(thread_max, 2), "proxy_threads_hot": round(hot, 1), "verdict": verdict}
    sat = RULES["component_saturated_fraction"]

    def out(label: str, confidence: str, why: str) -> dict:
        return {"label": label, "confidence": confidence, "why": why, "evidence": evidence}

    if verdict == "INVALID":
        return out("INVALID", "high", "the instrument refused the row: >0.5% of requests failed")
    if steal >= RULES["steal_significant"]:
        return out("HOST_SCHEDULING", "medium", f"steal {steal:.1%} >= {RULES['steal_significant']:.0%}: the VM "
                   "was not given the CPU it was scheduled for; a Lightsail/host limitation until proven otherwise")
    if redis_primary >= RULES["redis_primary_saturated_cores"]:
        return out("REPLAY_TIER", "medium", f"the Redis primary used {redis_primary:.2f} of its one core")
    if backend_budget and backend >= sat * backend_budget:
        return out("BACKEND", "medium", f"the backend used {backend:.2f} of its {backend_budget} worker cores")
    if refusals:
        return out("OS_CONNECTION_PATH", "medium", f"the kernel refused connection work during the window: {refusals}")
    if verdict == "CLIENT":
        if busy >= RULES["host_exhausted_busy"]:
            return out("INDETERMINATE", "high", f"still client-limited at the top of the ladder with the host "
                       f"{busy:.0%} busy: no spare CPU exists to separate proxy capacity from generator contention")
        return out("CLIENT_LIMITED", "high", "the rig still gained >5% from one more generator at the top rung; "
                   "the row is a floor, not the proxy's ceiling")
    serving = budget if cores == 0 else float(min(cores * max(workers, 1), vcpus))
    if proxy >= sat * budget or (cores > 0 and hot >= sat * serving):
        return out("PROXY_CPU", "high" if busy < RULES["host_exhausted_busy"] or cores == vcpus else "medium",
                   f"the proxy used {proxy:.1f} of its {budget:.0f}-core budget")
    if busy >= RULES["host_exhausted_busy"]:
        return out("INDETERMINATE", "medium", f"the host was {busy:.0%} busy while the proxy used only "
                   f"{proxy:.1f} of {budget:.0f} cores: co-located load competed for the CPU the proxy was given")
    if verdict is None and client >= sat * max(vcpus - proxy, 1.0):
        return out("CLIENT_LIMITED", "medium", "the canonical client consumed the CPU the proxy did not")
    if serving > 1 and thread_max >= RULES["hot_thread_cores"] and hot < 0.5 * serving:
        return out("PROXY_SERIALIZATION_OR_CONTENTION", "medium", f"one proxy thread ran at {thread_max:.2f} core while "
                   f"only {hot:.1f} of {serving:.0f} serving threads were hot: a serialized path")
    if proxy <= RULES["proxy_underused_fraction"] * budget:
        return out("PROXY_SERIALIZATION_OR_CONTENTION", "low", f"throughput stopped with the proxy at {proxy:.1f} of "
                   f"{budget:.0f} cores and the host not exhausted: look for a serialized path, lock or futex "
                   "contention — the diagnostic pass decides")
    return out("UNEXPLAINED", "low", "no rule fired: run the diagnostic profiling pass on this configuration")


def load_points(run_dir: Path, phase: str) -> list[dict]:
    return [read_json(p) for p in sorted((run_dir / phase).rglob("point.json"))]


def phase_a_summary(points: list[dict], vcpus: int) -> dict:
    out: dict[str, dict] = {}
    for topology in sorted({p["topology"] for p in points} - {"smoke"}):
        rows = []
        for p in sorted((p for p in points if p["topology"] == topology), key=lambda p: p["cores"]):
            valid = [r for r in p["reps"] if r["valid"]]
            tput = [r["throughput_rps"] for r in valid]
            rows.append({
                "cores": p["cores"], "workers_per_shard": p["workers_per_shard"], "status": p["status"],
                "reps_valid": len(valid), "reps_total": len(p["reps"]),
                "throughput_reps": tput, "throughput_median": median(tput), "throughput_min": min(tput, default=0.0),
                "p50_us_median": median([r["p50_us"] for r in valid]),
                "p99_us_median": median([r["p99_us"] for r in valid]),
                "p999_us_median": median([r["p999_us"] for r in valid]),
                "p99_us_max": max((r["p99_us"] for r in valid), default=None),
                "successes": sum(r["successes"] for r in valid), "failures": sum(r["failures"] for r in valid),
                "attribution": classify(p.get("telemetry", {}), cores=p["cores"], workers=p["workers_per_shard"],
                                        vcpus=vcpus, verdict=None, client_categories=("bench",),
                                        backend_budget=None),
            })
        curve = describe_curve([(r["cores"], r["throughput_median"]) for r in rows if r["reps_valid"]])
        out[topology] = {"rows": rows, "curve": curve}
    return out


def phase_b_summary(points: list[dict], vcpus: int) -> dict:
    out: dict[str, dict] = {}
    for sweep in sorted({p["sweep"] for p in points}):
        rows = []
        for cores in sorted({p["cores"] for p in points if p["sweep"] == sweep}):
            attempts = [p for p in points if p["sweep"] == sweep and p["cores"] == cores]
            finals = [a["final"] for a in attempts if a.get("final")]
            proxy_rps = [f["row"]["rps"] for f in finals if f["verdict"] == "PROXY"]
            all_rps = [f["row"]["rps"] for f in finals]
            med = median(proxy_rps)
            last = attempts[-1]
            rows.append({
                "cores": cores, "attempts": len(attempts), "verdicts": [f["verdict"] for f in finals],
                "rps_attempts": all_rps, "rps_proxy_median": med if proxy_rps else None,
                "rps_best": max(all_rps, default=0.0),
                "stable": bool(proxy_rps) and (max(proxy_rps) - min(proxy_rps)) / med <= 0.10 if med else False,
                "top_rung_connections": (last.get("final") or {}).get("connections_per_generator"),
                "attribution": classify(last.get("telemetry_final_rung") or last.get("telemetry", {}),
                                        cores=cores, workers=last["workers_per_shard"], vcpus=vcpus,
                                        verdict=(last.get("final") or {}).get("verdict"),
                                        client_categories=("loadgen", "rig"),
                                        backend_budget=RULES["rig_backend_workers"]),
            })
        curve_points = [(r["cores"], r["rps_proxy_median"]) for r in rows if r["rps_proxy_median"]]
        out[sweep] = {"rows": rows, "curve": describe_curve(curve_points) if curve_points else None}
    return out


def ceiling_statement(b_scaling: dict | None) -> dict:
    """The one-line answer, decided by the predeclared rules over the Phase B scaling sweep."""
    if not b_scaling or not b_scaling.get("rows"):
        return {"statement": "CEILING ATTRIBUTION: INDETERMINATE", "why": "no Phase B scaling sweep was measured"}
    rows = b_scaling["rows"]
    top = rows[-1]
    label = top["attribution"]["label"]
    curve = b_scaling.get("curve") or {}
    if label in {"INDETERMINATE", "CLIENT_LIMITED", "UNATTRIBUTED"} or top["rps_proxy_median"] is None:
        return {"statement": "CEILING ATTRIBUTION: INDETERMINATE",
                "why": f"the top of the sweep ({top['cores']} cores) is {label}: {top['attribution']['why']}"}
    crows = curve.get("rows", [])
    tail = crows[-2:] if len(crows) >= 2 else []
    stable_tail = all(next(r for r in rows if r["cores"] == c["cores"])["stable"] for c in tail)
    if len(tail) == 2 and all(c["plateau"] for c in tail) and stable_tail:
        knee_n = curve.get("plateau_from")
        ceiling = max(c["throughput"] for c in crows if c["cores"] >= (knee_n or 0))
        return {"statement": f"PROXY CEILING: REACHED — ~{ceiling:.0f} rps, flat from {knee_n} cores",
                "ceiling_rps": ceiling, "plateau_from_cores": knee_n, "limiting_component": label,
                "confidence": top["attribution"]["confidence"], "why": top["attribution"]["why"]}
    if curve.get("still_scaling_at_top"):
        return {"statement": "PROXY CEILING: NOT REACHED ON THIS HOST", "limiting_component": label,
                "why": f"incremental efficiency at the top of the sweep is still >= 0.5 ({top['cores']} cores, {label})"}
    return {"statement": "CEILING ATTRIBUTION: INDETERMINATE",
            "why": "the curve bends at the top but the plateau rule (two consecutive stable plateau points) is not met"}


def summarize_run(run_dir: Path, vcpus: int) -> dict:
    a = phase_a_summary(load_points(run_dir, "phase-a"), vcpus)
    b = phase_b_summary(load_points(run_dir, "phase-b"), vcpus)
    highest_a = max((t["curve"]["highest"] for t in a.values()), default=0.0)
    highest_b = max((r["rps_best"] for s in b.values() for r in s["rows"]), default=0.0)
    inconclusive = [f"A/{t}/c{r['cores']}: {r['status']}" for t, s in a.items() for r in s["rows"] if r["status"] != "COMPLETE"]
    inconclusive += [f"B/{s}/c{r['cores']}: {r['attribution']['label']}" for s, v in b.items() for r in v["rows"]
                     if r["attribution"]["label"] in {"INDETERMINATE", "UNEXPLAINED", "UNATTRIBUTED", "INVALID"}]
    return {"rules": RULES, "phase_a": a, "phase_b": b,
            "highest_demonstrated": {"phase_a_canonical_rps": highest_a, "phase_b_rig_rps": highest_b},
            "ceiling": ceiling_statement(b.get("scaling")),
            "inconclusive": inconclusive}


def render_markdown(summary: dict, manifest: dict) -> str:
    lines = ["# MCP-RE Lightsail ceiling experiment — summary", ""]
    ident = manifest.get("identity", {})
    lines += [f"- product: `{ident.get('release_tag')}` @ `{ident.get('product_commit')}`",
              f"- tooling: `{ident.get('tooling_commit')}`", f"- hardware class: `{manifest.get('hardware_class')}`",
              f"- **{summary['ceiling']['statement']}** — {summary['ceiling'].get('why', '')}", ""]
    lines += ["## Curve 1 — canonical security-path scaling (Phase A, cold mTLS, c=128, 8000 req)", ""]
    for topology, block in summary["phase_a"].items():
        curve = block["curve"]
        lines += [f"### topology `{topology}` — knee: {curve['knee']}, highest {curve['highest']:.0f} rps", "",
                  "| cores | reps | median rps | min rps | eff vs 1 | p50 µs | p99 µs | p999 µs | ok/fail | attribution |",
                  "|---:|---:|---:|---:|---:|---:|---:|---:|---|---|"]
        effs = {r["cores"]: r["efficiency_vs_1"] for r in curve["rows"]}
        for r in block["rows"]:
            eff = effs.get(r["cores"])
            lines.append(f"| {r['cores']} | {r['reps_valid']}/{r['reps_total']} | {r['throughput_median']:.0f} | "
                         f"{r['throughput_min']:.0f} | {'' if eff is None else f'{eff:.2f}'} | {r['p50_us_median']:.0f} | "
                         f"{r['p99_us_median']:.0f} | {r['p999_us_median']:.0f} | {r['successes']}/{r['failures']} | "
                         f"{r['attribution']['label']} |")
        lines.append("")
    lines += ["## Curve 2 — proxy saturation ceiling (Phase B, saturation rig)", ""]
    for sweep, block in summary["phase_b"].items():
        curve = block["curve"] or {}
        lines += [f"### sweep `{sweep}` — knee: {curve.get('knee')}, plateau from: {curve.get('plateau_from')}", "",
                  "| cores | attempts | verdicts | PROXY median rps | best rps | stable | attribution | confidence |",
                  "|---:|---:|---|---:|---:|---|---|---|"]
        for r in block["rows"]:
            med = "" if r["rps_proxy_median"] is None else f"{r['rps_proxy_median']:.0f}"
            lines.append(f"| {r['cores']} | {r['attempts']} | {','.join(r['verdicts'])} | {med} | {r['rps_best']:.0f} | "
                         f"{r['stable']} | {r['attribution']['label']} | {r['attribution']['confidence']} |")
        lines.append("")
    lines += ["## Highest demonstrated throughput", "",
              f"- canonical harness: {summary['highest_demonstrated']['phase_a_canonical_rps']:.0f} rps",
              f"- saturation rig: {summary['highest_demonstrated']['phase_b_rig_rps']:.0f} rps", "",
              "## Inconclusive measurements", ""]
    lines += [f"- {x}" for x in summary["inconclusive"]] or ["- none"]
    return "\n".join(lines) + "\n"
