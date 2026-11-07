# SPDX-License-Identifier: Apache-2.0
"""Comparing a fresh report with the anchor under the active tolerances."""

from __future__ import annotations

from pathlib import Path

LATENCY_BOUNDS = (
    ("p50", "p50_added_us_max_fraction"),
    ("p99", "p99_added_us_max_fraction"),
    ("p999", "p999_added_us_max_fraction"),
)


def _throughput(base_rps, got_rps, tol):
    """Throughput floor: fresh >= fraction * baseline."""
    min_rps = base_rps * tol["throughput_rps_min_fraction"]
    ok = got_rps >= min_rps
    check = ("throughput_rps", f">= {min_rps:.1f}", f"{got_rps:.1f}", ok)
    return check, (None if ok else "throughput regressed below floor")


def _latency(bound, base_lat, got_lat, tol):
    """Latency ceiling: fresh <= fraction * baseline, for one percentile."""
    pct, key = bound
    ceil = base_lat[pct] * tol[key]
    val = got_lat[pct]
    ok = val <= ceil
    check = (f"{pct}_added_us", f"<= {ceil:.0f}", f"{val}", ok)
    return check, (None if ok else f"{pct} added latency exceeded ceiling")


def evaluate(base, got, tol):
    """`(checks, failures)` for the fresh results against the anchor's."""
    outcomes = [_throughput(base["throughput_rps"], got["throughput_rps"], tol)]
    outcomes += [
        _latency(bound, base["added_latency_us"], got["added_latency_us"], tol)
        for bound in LATENCY_BOUNDS
    ]
    checks = [check for check, _ in outcomes]
    failures = [failure for _, failure in outcomes if failure]
    # A run that produced request failures is never a pass.
    if got.get("failures", 0) != 0:
        failures.append(f"{got['failures']} request failure(s) in the fresh run")
    return checks, failures


def print_checks(report, baseline_path, base, checks):
    base_lat = base["added_latency_us"]
    width = max(len(c[0]) for c in checks)
    print("=== ADR-051 §7 local-regression SLO gate ===")
    print(f"hardware class: {report['config']['hardware_class']}")
    print(
        f"baseline: {Path(baseline_path).name}  (anchor rps={base['throughput_rps']:.1f}, "
        f"p50={base_lat['p50']}us p99={base_lat['p99']}us p999={base_lat['p999']}us)"
    )
    for name, bound, val, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<{width}}  {val:>10}  (bound {bound})")
