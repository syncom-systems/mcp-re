# SPDX-License-Identifier: Apache-2.0
"""The theorem axes and their conjunction — Ruling 35 §3.

`review_current` is the owner's review, `evidence_established` is the supporting units'
freshness, and `currently_verified` is both plus every theorem depended on. They are kept
apart so neither can stand in for the other.
"""

from __future__ import annotations

from dataclasses import dataclass

from _review_model import REVIEWED
from _review_state import (
    assumption_review_state,
    backed_review_state,
    combined_review,
    semantic_review_state,
)


@dataclass(frozen=True)
class Basis:
    """What every theorem's state is derived from, shared across the registry."""

    fingerprints: dict[str, dict]
    reviews: dict[tuple[str, str], dict]
    unit_states: dict[str, tuple[str, str]]
    premises: dict[str, dict[str, str] | None]
    backing: dict[str, tuple[bool, str]]
    review_digests: dict[str, dict | None]


def evidence(state: dict) -> tuple[str, str]:
    """EVIDENCE_ESTABLISHED, locally: a successful run vouches for every supporting unit at
    its full current fingerprint — semantic inputs, lane identities, toolchain, generated
    model and policy revisions. `_graph.derive_unit_state` is the authority; FRESH is the
    only state that establishes."""
    if state["deprecated"]:
        return "DEPRECATED", "a withdrawn claim establishes nothing"
    if not state["supporting_units"]:
        return "NO_SUPPORT", "no supporting unit: no evidence exists"
    dirty = sorted(
        f"unit://{unit} {unit_state}"
        for unit, unit_state in state["unit_states"].items()
        if unit_state != "FRESH"
    )
    if dirty:
        return "NOT_ESTABLISHED", ", ".join(dirty)
    return "ESTABLISHED", f"{len(state['supporting_units'])} supporting unit(s) FRESH"


def _theorem_state(basis: Basis, theorem_id: str, entry: dict) -> dict:
    supporting = [str(t).removeprefix("unit://") for t in entry.get("supported_by", [])]
    unit_axis = [basis.unit_states.get(unit, ("UNKNOWN", "not declared")) for unit in supporting]
    record = basis.reviews.get(("specification", theorem_id))
    spec = backed_review_state(
        basis.fingerprints[theorem_id], record, basis.backing.get(theorem_id)
    )
    closure = basis.premises.get(theorem_id)
    premise_review = {
        asm: assumption_review_state(asm, digest, basis.reviews, basis.backing)
        for asm, digest in sorted((closure or {}).items())
    }
    semantic = semantic_review_state(basis.review_digests.get(theorem_id), record)
    state = {
        "deprecated": bool(entry.get("replaced_by")),
        "supporting_units": supporting,
        "unit_states": {unit: s for unit, (s, _) in zip(supporting, unit_axis)},
        "specification_review": spec,
        "premise_review": premise_review,
        "semantic_review": semantic,
        "review": combined_review(spec, closure, premise_review, semantic),
    }
    state["review_current"] = state["review"][0] == REVIEWED
    state["evidence"] = evidence(state)
    state["evidence_established"] = state["evidence"][0] == "ESTABLISHED"
    state["currently_verified"] = state["review_current"] and state["evidence_established"]
    return state


def _has_unverified_dependency(result: dict[str, dict], entry: dict) -> bool:
    return any(
        not result.get(dep, {}).get("currently_verified") for dep in entry.get("depends_on", [])
    )


def _propagate_dependencies(result: dict[str, dict], entries: dict[str, dict]) -> None:
    """Fixpoint over `depends_on`: a premise theorem that is not currently verified takes
    every claim above it with it."""
    changed = True
    while changed:
        changed = False
        for theorem_id, state in result.items():
            if state["currently_verified"] and _has_unverified_dependency(
                result, entries[theorem_id]
            ):
                state["currently_verified"] = False
                changed = True


def theorem_assurance(theorems: dict, basis: Basis) -> dict[str, dict]:
    """Two axes and their conjunction — Ruling 35 §3.

        review_current        the owner's specification review covers the CURRENT claim
                              fingerprint, the ledger backs it, every assumption in its
                              premise closure is reviewed and backed at its CURRENT digest,
                              and the record's `review_digest` equals the current semantic
                              evidence digest (`_fingerprint.review_digest`)
        evidence_established  not deprecated, supported, and every supporting unit FRESH —
                              an attestation at its full current fingerprint
        currently_verified    review_current AND evidence_established, and every theorem it
                              depends on is itself currently verified

    The two halves are reported apart so neither can stand in for the other: a fresh
    prover run over code nobody re-read is not current, and a current review over evidence
    nobody re-ran is not established. Only `currently_verified` may be read as "holds".

    `basis.premises` maps each theorem to its premise closure
    (`_fingerprint.theorem_premises`); `basis.review_digests` to its semantic evidence digest
    (`_fingerprint.theorem_review_digests`). A theorem missing from either is unknown there,
    and not current. `basis.backing` maps subjects to `_approvals.ledger_state`.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    result = {tid: _theorem_state(basis, tid, entry) for tid, entry in entries.items()}
    _propagate_dependencies(result, entries)
    return result
