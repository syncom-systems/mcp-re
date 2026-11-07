# SPDX-License-Identifier: Apache-2.0
"""The state of one unit from its own inputs alone, before any propagation: its attestation
compared against the current derivation, component by component."""

from __future__ import annotations

from _graph_attestation import Attestation
from _graph_states import (
    COMPONENT_STATE,
    STATE_PRECEDENCE,
    UNRESOLVED_COMPONENT,
)


def _first_by_precedence(states: set[str]) -> str:
    for state in STATE_PRECEDENCE:
        if state in states:
            return state
    return "UNKNOWN"


def _unknown_verdict(name: str, value: object, recorded: dict) -> tuple[str, str] | None:
    """The UNKNOWN verdict a component forces, or None when it can be compared and classified."""
    if name not in recorded:
        return (
            "UNKNOWN",
            f"the attestation records no `{name}`: it predates the current encoding, "
            f"so what it certified cannot be compared",
        )
    if recorded[name] == value or name in COMPONENT_STATE:
        return None
    why = UNRESOLVED_COMPONENT.get(name)
    return "UNKNOWN", (
        f"`{name}` changed and is deliberately unclassified: {why}"
        if why
        else f"`{name}` changed and this engine cannot classify it. It is in "
        f"neither COMPONENT_STATE nor UNRESOLVED_COMPONENT, which the component "
        f"census forbids — so the census is not running where this ran."
    )


def _unmoved_verdict(attestation: Attestation, current: dict) -> tuple[str, str]:
    if attestation.fingerprint != current["fingerprint"]:
        return (
            "UNKNOWN",
            "every recorded component matches but the fingerprint does not: the "
            "encoding itself changed, so the comparison means something different",
        )
    return "FRESH", "every recorded input is unchanged"


def _preflight_verdict(attestation: Attestation | None) -> tuple[str, str] | None:
    """The verdict an absent or failed attestation settles before any comparison, or None."""
    if attestation is None:
        return "UNKNOWN", "no attestation: this unit has never been established fresh"
    if attestation.evidence.get("verus") == "fail" or attestation.evidence.get("lean") == "fail":
        return "BLOCKED", "a required proof failed; no freshness may be issued from here"
    return None


def _compare_components(attestation: Attestation, current: dict) -> tuple[str, str]:
    recorded = attestation.components
    compared = [
        (name, value) for name, value in current["components"].items() if name != "encoding_version"
    ]
    for name, value in compared:
        verdict = _unknown_verdict(name, value, recorded)
        if verdict is not None:
            return verdict
    moved = [name for name, value in compared if recorded[name] != value]
    if not moved:
        return _unmoved_verdict(attestation, current)
    differing = {COMPONENT_STATE[name] for name in moved}
    return _first_by_precedence(differing), "changed: " + ", ".join(sorted(moved))


def derive_unit_state(unit_id: str, current: dict, attestations: dict) -> tuple[str, str]:
    """The state of one unit from its own inputs alone, before any propagation.

    Returns `(state, reason)`. The reason is for the reviewer, and it names the component,
    because "this unit is dirty" without saying which input moved sends someone to re-read
    everything — the outcome this whole system exists to avoid.
    """
    attestation = attestations.get(unit_id)
    settled = _preflight_verdict(attestation)
    if settled is not None:
        return settled
    return _compare_components(attestation, current)
