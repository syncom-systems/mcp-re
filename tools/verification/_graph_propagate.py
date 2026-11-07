# SPDX-License-Identifier: Apache-2.0
"""Propagating invalidation along typed edges, and the context closure a reviewer reads."""

from __future__ import annotations

from dataclasses import dataclass

from _graph_attestation import Attestation

_NOT_DECLARED = ("UNKNOWN", "not declared")


@dataclass(frozen=True)
class _Producers:
    """What a sealed edge consults about a producer: its attestation and its current derivation."""

    current: dict[str, dict]
    attestations: dict[str, Attestation]

    def contract_unchanged(self, producer: str) -> bool:
        """Whether the producer's exported contract is what its attestation recorded."""
        attestation = self.attestations.get(producer)
        now = self.current.get(producer)
        if not (attestation and now):
            return False
        recorded = attestation.components.get("exported_contracts")
        return recorded == now["components"].get("exported_contracts")


def _blocked_update(kind: str, producer: str, consumer_state: str) -> tuple[str, str] | None:
    """A BLOCKED producer is not staleness, and the difference is the whole point of
    keeping two words. DIRTY_* means "this evidence can be re-derived". BLOCKED
    means "no valid freshness may be issued until something OUTSIDE this unit is
    repaired" — and no amount of re-running the consumer repairs a failed
    prerequisite. So it propagates as BLOCKED, and a seal does not stop it: a seal
    is a claim about a contract being the whole of the consumer's reasoning, which
    says nothing when the proof establishing that contract has failed.

    It also escalates a consumer that is merely dirty, because BLOCKED is strictly
    the stronger statement about what may be issued.
    """
    if consumer_state == "BLOCKED":
        return None
    return (
        "BLOCKED",
        f"required dependency {producer} is BLOCKED over a {kind} edge; "
        "re-running this unit cannot repair a failed prerequisite",
    )


def _sealed_update(
    edge: dict, producer_state: str, producers: _Producers
) -> tuple[str, str] | None:
    """The sealed edge's promise, and its exact limits."""
    producer = edge["from"]
    stops_here = producer_state in {"DIRTY_SELF", "DIRTY_EVIDENCE"}
    if stops_here and producers.contract_unchanged(producer):
        # Source moved, contract did not, no proof failure: propagation
        # stops. This is the ONLY case where dirtiness does not flow.
        return None
    return (
        "DIRTY_DEPENDENCY",
        f"sealed on {edge.get('contract')}, but the producer is "
        f"{producer_state}, which a seal does not stop",
    )


def _edge_update(
    edge: dict, result: dict[str, tuple[str, str]], producers: _Producers
) -> tuple[str, str] | None:
    """What this edge does to its consumer's `(state, reason)`, or None when nothing flows."""
    kind = edge["kind"]
    if kind == "REVIEW_CONTEXT":
        return None
    # Direction is not decorative: `from` PRODUCES the evidence, `to` CONSUMES it,
    # and invalidation flows only that way. A graph that is internally consistent
    # while propagating backwards would report exactly the wrong unit as sound,
    # which is why `test_invalidation` pins the asymmetry.
    producer, consumer = edge["from"], edge["to"]
    producer_state = result.get(producer, _NOT_DECLARED)[0]
    consumer_state = result.get(consumer, _NOT_DECLARED)[0]
    if producer_state == "FRESH":
        return None
    if producer_state == "BLOCKED":
        return _blocked_update(kind, producer, consumer_state)
    if consumer_state != "FRESH":
        return None
    if kind == "CONTRACT_CONSUMES" and edge.get("sealed"):
        return _sealed_update(edge, producer_state, producers)
    return "DIRTY_DEPENDENCY", f"{producer} is {producer_state} over an unsealed {kind} edge"


def propagate(
    states: dict[str, tuple[str, str]],
    edges: list[dict],
    current: dict[str, dict],
    attestations: dict[str, Attestation],
) -> dict[str, tuple[str, str]]:
    """Push invalidation along typed edges until it stops moving.

    Three rules. The first is about what a failure MEANS; the other two are about how far
    ordinary staleness travels, and the difference between them is the value of the formal
    layer:

      * A `BLOCKED` producer blocks its consumers, over every propagating edge kind and
        through any seal. Freshness is a property of the whole declared evidence closure,
        not of a unit's own latest verifier result, so a consumer whose own theorem still
        passes may not issue freshness while a required prerequisite has failed.


      * An UNSEALED `CONTRACT_CONSUMES` or a `COMPILE_DEPENDENCY` propagates ANY producer
        dirtiness. Conservative, and the default: without a proved unchanged contract there
        is no ground to claim the consumer's reasoning survived.
      * A SEALED `CONTRACT_CONSUMES` propagates only when the producer's exported CONTRACT
        changed, or its proof failed, or the assumptions/toolchain under that proof moved.
        Producer source churn alone stops at the producer.

    `REVIEW_CONTEXT` never propagates — that is what makes it context closure rather than
    review closure (§3).
    """
    result = dict(states)
    producers = _Producers(current, attestations)
    changed = True
    while changed:
        changed = False
        for edge in edges:
            update = _edge_update(edge, result, producers)
            if update is not None:
                result[edge["to"]] = update
                changed = True
    return result


def context_closure(unit_ids: set[str], edges: list[dict]) -> set[str]:
    """Units a reviewer should READ, which is not the same as units to re-review (§3).

    Every neighbour of a dirty unit, by any edge kind including `REVIEW_CONTEXT`, and
    excluding the dirty set itself. Belonging here carries no invalidation: keeping the two
    apart is what stops the graph from either invalidating the repository for every local
    change, or showing a reviewer only the lines that moved.
    """
    out: set[str] = set()
    for edge in edges:
        if edge["from"] in unit_ids:
            out.add(edge["to"])
        if edge["to"] in unit_ids:
            out.add(edge["from"])
    return out - unit_ids
