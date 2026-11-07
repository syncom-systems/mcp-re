# SPDX-License-Identifier: Apache-2.0
"""The markdown summary of a run: header, the two curves, the highest throughputs."""

from __future__ import annotations


def _header(summary: dict, manifest: dict) -> list[str]:
    ident = manifest.get("identity", {})
    pool = manifest.get("replay_pool", {})
    return ["# MCP-RE Lightsail ceiling experiment — summary", "",
            f"- product: `{ident.get('release_tag')}` @ `{ident.get('product_commit')}`",
            f"- tooling: `{ident.get('tooling_commit')}`", f"- hardware class: `{manifest.get('hardware_class')}`",
            f"- replay redis pool: {pool.get('flag')}; expected {pool.get('expected')} connections",
            f"- **{summary['ceiling']['statement']}** — {summary['ceiling'].get('why', '')}", ""]


def _phase_a_line(r: dict, eff: float | None) -> str:
    return (f"| {r['cores']} | {r['reps_valid']}/{r['reps_total']} | {r['throughput_median']:.0f} | "
            f"{r['throughput_min']:.0f} | {'' if eff is None else f'{eff:.2f}'} | {r['p50_us_median']:.0f} | "
            f"{r['p99_us_median']:.0f} | {r['p999_us_median']:.0f} | {r['successes']}/{r['failures']} | "
            f"{r['attribution']['label']} |")


def _phase_a(summary: dict) -> list[str]:
    lines = ["## Curve 1 — canonical security-path scaling (Phase A, cold mTLS, c=128, 8000 req)", ""]
    for topology, block in summary["phase_a"].items():
        curve = block["curve"]
        lines += [f"### topology `{topology}` — knee: {curve['knee']}, highest {curve['highest']:.0f} rps", "",
                  "| cores | reps | median rps | min rps | eff vs 1 | p50 µs | p99 µs | p999 µs | ok/fail | attribution |",
                  "|---:|---:|---:|---:|---:|---:|---:|---:|---|---|"]
        effs = {r["cores"]: r["efficiency_vs_1"] for r in curve["rows"]}
        lines += [_phase_a_line(r, effs.get(r["cores"])) for r in block["rows"]]
        lines.append("")
    return lines


def _queue_cells(q: dict) -> str:
    if not q.get("available"):
        return " |  | "
    qbuf = q["qbuf_per_conn_mean_bytes"]
    return (f"{q['store_conns_max']} | {q['blocked_in_wait_mean']:.1f} | "
            f"{'' if qbuf is None else round(qbuf)}")


def _phase_b_line(r: dict) -> str:
    med = "" if r["rps_proxy_median"] is None else f"{r['rps_proxy_median']:.0f}"
    queue = _queue_cells(r.get("redis_queue") or {})
    return (f"| {r['cores']} | {r['attempts']} | {','.join(r['verdicts'])} | {med} | {r['rps_best']:.0f} | "
            f"{r['stable']} | {r['attribution']['label']} | {r['attribution']['confidence']} | "
            f"{','.join(map(str, r.get('replay_pool_stated', [])))} | {queue} |")


def _phase_b(summary: dict) -> list[str]:
    lines = ["## Curve 2 — proxy saturation ceiling (Phase B, saturation rig)", ""]
    for sweep, block in summary["phase_b"].items():
        curve = block["curve"] or {}
        lines += [f"### sweep `{sweep}` — knee: {curve.get('knee')}, plateau from: {curve.get('plateau_from')}", "",
                  "| cores | attempts | verdicts | PROXY median rps | best rps | stable | attribution | confidence "
                  "| pool stated | Redis store conns | blocked in WAIT | qbuf/conn B |",
                  "|---:|---:|---|---:|---:|---|---|---|---|---:|---:|---:|"]
        lines += [_phase_b_line(r) for r in block["rows"]]
        lines.append("")
    return lines


def _footer(summary: dict) -> list[str]:
    highest = summary["highest_demonstrated"]
    lines = ["## Highest demonstrated throughput", "",
             f"- canonical harness: {highest['phase_a_canonical_rps']:.0f} rps",
             f"- saturation rig: {highest['phase_b_rig_rps']:.0f} rps", "",
             "## Inconclusive measurements", ""]
    return lines + ([f"- {x}" for x in summary["inconclusive"]] or ["- none"])


def render_markdown(summary: dict, manifest: dict) -> str:
    lines = _header(summary, manifest) + _phase_a(summary) + _phase_b(summary) + _footer(summary)
    return "\n".join(lines) + "\n"
