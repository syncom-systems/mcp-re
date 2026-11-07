# SPDX-License-Identifier: Apache-2.0
"""Run the gate: derive the registry, read the boundary, compare, report."""

from __future__ import annotations

import sys

from _claim_surface.errors import Failure
from _claim_surface.mapping import mapping_defects
from _claim_surface.movement import measure_movement
from _claim_surface.spec import Surfaces, read_surfaces
from _claim_surface.standing import Registry, derive_registry


def _ok_line(registry: Registry, surfaces: Surfaces) -> str:
    carried = registry.carried_roots()
    return (
        f"claim-surface gate: OK — {len(registry.roots)} declared root(s), "
        f"{len(surfaces.claims)} published claim(s), {len(surfaces.gaps)} open §4 area(s), "
        f"{len(surfaces.settled)} settled, every claimed root reviewed at its current "
        f"fingerprint"
        + (
            f" or carried there by a recorded Phase-1 correction ({carried} of them)."
            if carried
            else "."
        )
    )


def _run() -> int:
    registry = derive_registry()
    surfaces = read_surfaces()
    if not surfaces.claims:
        raise Failure(
            "FAIL: §2 of the security boundary parsed to no claim rows. An unreadable "
            "claim surface must not report as an agreeing one."
        )
    movement = measure_movement(registry)
    found = mapping_defects(registry.roots, surfaces, registry.standing) + movement.defects
    if found:
        print(f"claim-surface gate: {movement.note}", file=sys.stderr)
        print("claim-surface gate: FAIL", file=sys.stderr)
        for defect in found:
            print(f"  - {defect}", file=sys.stderr)
        return 1
    print(f"claim-surface gate: {movement.note}")
    print(_ok_line(registry, surfaces))
    return 0


def judge() -> int:
    try:
        return _run()
    except Failure as failure:
        for line in failure.lines:
            print(line, file=sys.stderr)
        return 1
