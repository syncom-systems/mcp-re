# SPDX-License-Identifier: Apache-2.0
"""The gate's command line: gate a fresh report, or exercise the comparability rules."""

from __future__ import annotations

import argparse
import sys

from _adr051_slo.anchor import load_json, resolve_anchor, unanchored
from _adr051_slo.config import DEFAULT_TARGETS
from _adr051_slo.regression import evaluate, print_checks
from _adr051_slo.selftest import selftest


def _parser():
    ap = argparse.ArgumentParser(description="ADR-051 §7 local-regression SLO gate")
    ap.add_argument("--report", help="fresh harness report JSON (MCP_RE_LOADGEN_OUT)")
    ap.add_argument("--baseline", default=None,
                    help="committed baseline JSON (default: the anchor declared for the "
                         "report's own hardware class)")
    ap.add_argument("--targets", default=DEFAULT_TARGETS, help="committed SLO targets JSON")
    ap.add_argument("--selftest", action="store_true", help="exercise the comparability rules")
    return ap


def _gate(report, baseline_path, targets_path):
    baseline = load_json(baseline_path)
    reg = load_json(targets_path).get("local_regression", {})
    if reg.get("status") != "active":
        print("adr051-slo-gate: local_regression is not active; nothing to gate.")
        return 0
    base = baseline["anchor"]["results"]
    checks, failures = evaluate(base, report["results"], reg["tolerances"])
    print_checks(report, baseline_path, base, checks)
    if failures:
        print("\nRESULT: FAIL — " + "; ".join(failures), file=sys.stderr)
        return 1
    print("\nRESULT: PASS — within local-regression tolerances.")
    return 0


def run():
    ap = _parser()
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.report:
        ap.error("--report is required (or --selftest)")
    report = load_json(args.report)
    baseline_path, reason = resolve_anchor(report, args.baseline)
    if baseline_path is None:
        return unanchored(report, reason)
    return _gate(report, baseline_path, args.targets)
