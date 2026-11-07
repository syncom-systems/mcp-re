# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree."""

from __future__ import annotations

import argparse
import sys

import _ratchet

from _assurance_obligation.config import REGISTRY_REL, STATUSES
from _assurance_obligation.defects import defects
from _assurance_obligation.registry import base_unit_paths, current_unit_paths, load_registry, obligations, owing
from _assurance_obligation.selftest import selftest
from _assurance_obligation.succession import Basis


def _states(registry: dict[str, dict]) -> dict[str, int]:
    states = {status: 0 for status in STATUSES}
    for row in registry.values():
        states[row["status"]] += 1
    return states


def _origin(registry: dict[str, dict], before: dict[str, dict]) -> str:
    # Counted against the BASE, not against the presence of a `succeeds` field: once a
    # successor row is in the base it is pre-existing, and its succession fields are
    # provenance. A summary that counted the field would keep reporting an authorization
    # that was spent merges ago.
    admitted = sum(1 for unit, row in registry.items() if row.get("succeeds") and unit not in before)
    if not admitted:
        return "all pre-existing at the baseline"
    return (
        f"{len(registry) - admitted} pre-existing at the baseline and {admitted} "
        f"admitted by SUCCESSION from a row the base held"
    )


def _summary(registry: dict[str, dict], before: dict[str, dict]) -> str:
    states = _states(registry)
    reachable = sum(1 for row in registry.values() if row.get("root_reachable"))
    return (
        f"assurance-obligation gate: OK — {len(registry)} open N1 obligation(s), all "
        f"measured and {_origin(registry, before)} "
        f"({states['unreviewed']} unreviewed, {states['reviewed-action-required']} "
        f"reviewed-action-required, {states['reviewed-exception']} reviewed-exception; "
        f"{reachable} root-reachable). Registry did not grow, no status returned to "
        f"unreviewed, and every row names an obligation that is still owed. Each remains "
        f"INCOMPLETE — the registry bounds the population, it does not discharge anything."
    )


def _no_base_summary(measured: dict, base: str) -> str:
    return (
        f"assurance-obligation gate: registry consistent with {len(measured)} measured "
        f"obligation(s), and {base} holds no registry, so there was nothing for the "
        f"shrink-only and one-way-status rules to compare against."
    )


def judge(base: str) -> int:
    try:
        registry = load_registry()
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    measured = owing()
    baseline = obligations().at(base)
    if isinstance(baseline, _ratchet.Unreadable):
        print(f"FAIL: {_ratchet.unreadable_problem(REGISTRY_REL, base, baseline)}", file=sys.stderr)
        return 1
    before = baseline.entries if isinstance(baseline, _ratchet.Present) else None
    found = defects(measured, registry, Basis(before, base_unit_paths(base), current_unit_paths()))
    if found:
        for entry in found:
            print(f"FAIL: {entry}", file=sys.stderr)
        return 1
    print(_no_base_summary(measured, base) if before is None else _summary(registry, before))
    return 0


def main(description: str) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return judge(args.base)
