# SPDX-License-Identifier: Apache-2.0
"""Aggregation, the predeclared knee/plateau rules, and bottleneck attribution.

EVERY THRESHOLD IS DECLARED BEFORE THE RUN. They are recorded in the run manifest
(`RULES`) and in docs/bench/lightsail-ceiling-runbook.md, and a summary states the rule set
it was produced under. None of them is a pass/fail threshold for MCP-RE: this experiment
characterizes a new hardware context and has no predeclared floor. They decide only how a
curve is DESCRIBED (where its knee is, whether it has plateaued) and which component the
host evidence points at when it does.

The two curves are never merged: Phase A is the canonical security-path curve measured by a
client that signs on its own hot path; Phase B is the proxy-ceiling curve measured by the
saturation rig. A Phase A plateau that Phase B does not share is a CLIENT plateau.

The parts live beside this file: `analysis_rules` (the rule set and curve description),
`analysis_attribution` (which component the telemetry points at), `analysis_rows`
(one row per measured point), `analysis_summary` (per-sweep summaries), `analysis_ceiling` (the
ceiling statement) and `analysis_render` (the markdown).
"""

from __future__ import annotations

from analysis_attribution import PointSetting, classify
from analysis_ceiling import ceiling_statement
from analysis_render import render_markdown
from analysis_rules import RULES, describe_curve, incremental_efficiency, median
from analysis_summary import (
    load_points,
    phase_a_summary,
    phase_b_summary,
    summarize_run,
)

__all__ = [
    "RULES", "PointSetting", "ceiling_statement", "classify", "describe_curve",
    "incremental_efficiency", "load_points", "median", "phase_a_summary", "phase_b_summary",
    "render_markdown", "summarize_run",
]
