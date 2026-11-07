# SPDX-License-Identifier: Apache-2.0
"""Aggregating a run's measured points into per-sweep summaries and the ceiling statement."""

from __future__ import annotations

from pathlib import Path

from analysis_ceiling import ceiling_statement
from analysis_rows import phase_a_row, phase_b_row
from analysis_rules import RULES, describe_curve
from common import read_json


def load_points(run_dir: Path, phase: str) -> list[dict]:
    return [read_json(p) for p in sorted((run_dir / phase).rglob("point.json"))]


def phase_a_summary(points: list[dict], vcpus: int) -> dict:
    out: dict[str, dict] = {}
    for topology in sorted({p["topology"] for p in points} - {"smoke"}):
        ordered = sorted((p for p in points if p["topology"] == topology), key=lambda p: p["cores"])
        rows = [phase_a_row(p, vcpus) for p in ordered]
        curve = describe_curve([(r["cores"], r["throughput_median"]) for r in rows if r["reps_valid"]])
        out[topology] = {"rows": rows, "curve": curve}
    return out


def phase_b_summary(points: list[dict], vcpus: int) -> dict:
    out: dict[str, dict] = {}
    for sweep in sorted({p["sweep"] for p in points}):
        rows = []
        for cores in sorted({p["cores"] for p in points if p["sweep"] == sweep}):
            attempts = [p for p in points if p["sweep"] == sweep and p["cores"] == cores]
            rows.append(phase_b_row(attempts, cores, vcpus))
        curve_points = [(r["cores"], r["rps_proxy_median"]) for r in rows if r["rps_proxy_median"]]
        out[sweep] = {"rows": rows, "curve": describe_curve(curve_points) if curve_points else None}
    return out


def _inconclusive_a(a: dict) -> list[str]:
    return [f"A/{t}/c{r['cores']}: {r['status']}" for t, s in a.items() for r in s["rows"]
            if r["status"] != "COMPLETE"]


def _inconclusive_b(b: dict) -> list[str]:
    return [f"B/{s}/c{r['cores']}: {r['attribution']['label']}" for s, v in b.items() for r in v["rows"]
            if r["attribution"]["label"] in {"INDETERMINATE", "UNEXPLAINED", "UNATTRIBUTED", "INVALID"}]


def summarize_run(run_dir: Path, vcpus: int) -> dict:
    a = phase_a_summary(load_points(run_dir, "phase-a"), vcpus)
    b = phase_b_summary(load_points(run_dir, "phase-b"), vcpus)
    highest_a = max((t["curve"]["highest"] for t in a.values()), default=0.0)
    highest_b = max((r["rps_best"] for s in b.values() for r in s["rows"]), default=0.0)
    return {"rules": RULES, "phase_a": a, "phase_b": b,
            "highest_demonstrated": {"phase_a_canonical_rps": highest_a, "phase_b_rig_rps": highest_b},
            "ceiling": ceiling_statement(b.get("scaling")),
            "inconclusive": _inconclusive_a(a) + _inconclusive_b(b)}
