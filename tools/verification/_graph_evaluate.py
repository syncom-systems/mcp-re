# SPDX-License-Identifier: Apache-2.0
"""The full derivation: per-unit states, propagation, frontier and context closure."""

from __future__ import annotations

from _graph_attestation import Attestation
from _graph_derive import derive_unit_state
from _graph_propagate import context_closure, propagate


def evaluate(
    units: list[dict],
    edges: list[dict],
    current: dict[str, dict],
    attestations: dict[str, Attestation],
) -> dict:
    """The full derivation: per-unit states, propagation, frontier, context closure."""
    states = {
        unit["id"]: derive_unit_state(unit["id"], current[unit["id"]], attestations)
        for unit in units
    }
    states = propagate(states, edges, current, attestations)
    dirty = {unit_id for unit_id, (state, _) in states.items() if state != "FRESH"}
    return {
        "states": states,
        "review_closure": sorted(dirty),
        "context_closure": sorted(context_closure(dirty, edges)),
        "fresh": sorted(set(states) - dirty),
    }
