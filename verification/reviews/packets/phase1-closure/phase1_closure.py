#!/usr/bin/env python3
"""ADR-MCPRE-068 Phase-1 closure derivation.

Re-derives every closure-report number FROM THE TREE it is run in. It aggregates
nothing from branch-local reports and reads no prior measurement: every figure
below comes from the registries and tooling present at this exact SHA.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import _phase1_checks as checks  # noqa: E402
import _phase1_corrections as corrections  # noqa: E402
import _phase1_registry as registry  # noqa: E402
import _phase1_repository as repository  # noqa: E402
import _phase1_root_state as root_state  # noqa: E402


def derive() -> dict:
    out = {}
    registry.head_state(out)
    registries = registry.registry_numbers(out)
    recs = corrections.correction_records(out)
    shapes = corrections.correction_shapes(out, recs)
    base_units = root_state.read_baseline(out)
    root_state.root_state(out, registries, shapes, base_units)
    repository.packets(out, recs)
    repository.unmerged_branches(out)
    repository.open_prs(out)
    checks.unit_fanout(out, registries)
    checks.gates(out)
    return out


if __name__ == "__main__":
    print(json.dumps(derive(), indent=1, sort_keys=False))
