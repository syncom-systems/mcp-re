# SPDX-License-Identifier: Apache-2.0
"""The admission rules for typed edges — ADR-MCPRE-059 §4."""

from __future__ import annotations

from _record_rules import reject_unknown
from _record_rules import require
from _registries import ManifestError


#: Typed edge kinds, ADR-MCPRE-059 §4. Collapsing these into one "depends on" relation is
#: forbidden once invalidation is enforced, so the set is closed here.
EDGE_KINDS = {
    "COMPILE_DEPENDENCY",
    "CONTRACT_CONSUMES",
    "PROOF_DEPENDENCY",
    "TEST_EVIDENCE",
    "TRUSTS_ASSUMPTION",
    "GENERATED_FROM",
    "REVIEW_CONTEXT",
}


_EDGE_KEYS = {"kind", "from", "to", "contract", "sealed", "sealed_by", "rationale"}


def validate_edges(
    where: str, edges: list[dict], unit_ids: set[str], exports: dict[str, set[str]]
) -> None:
    """The admission rules for typed edges — ADR-MCPRE-059 §4.

    Separate from `load_verification` because the rules below are a proposition about what
    an edge kind MEANS, and a proposition whose only exercise is that the committed manifest
    happens to satisfy it has never been shown to refuse anything.

    The contract rule, and why it is stated for every contract edge rather than only for a
    sealed one: `CONTRACT_CONSUMES` asserts a relation to the producer's PUBLISHED INTERFACE,
    which is a stronger claim than "this consumer compiles against that producer". Nine edges
    carried the kind while naming no contract, and none of their producers exported one — so
    the graph said "contract relation" about nine compile-time dependencies, and
    `consumed_contracts` had no relation to derive itself from. An edge that cannot name a
    contract its own producer exports is a `COMPILE_DEPENDENCY`; the fix is never to invent
    the contract.

    `sealed` is an ADDITIONAL property of an already-valid contract relation — the claim that
    the contract is the WHOLE of the consumer's reasoning — not what makes the relation a
    contract relation. So an unsealed contract edge is legitimate, and the contract is
    required either way.
    """
    for index, edge in enumerate(edges):
        ewhere = f"{where} [[edge]] #{index}"
        _validate_edge_shape(ewhere, edge, unit_ids)
        if edge["kind"] == "CONTRACT_CONSUMES":
            _validate_contract_relation(ewhere, edge, exports)
        if edge.get("sealed"):
            _validate_seal(ewhere, edge)


def _validate_edge_shape(ewhere: str, edge: dict, unit_ids: set[str]) -> None:
    """An edge has known keys, a closed kind, and endpoints that are declared units."""
    reject_unknown(ewhere, edge, _EDGE_KEYS)
    require(ewhere, edge, {"kind", "from", "to"})
    if edge["kind"] not in EDGE_KINDS:
        raise ManifestError(
            f"{ewhere}: kind {edge['kind']!r} not one of {sorted(EDGE_KINDS)}"
        )
    for endpoint in ("from", "to"):
        if edge[endpoint] not in unit_ids:
            raise ManifestError(
                f"{ewhere}: {endpoint} {edge[endpoint]!r} is not a declared unit"
            )


def _validate_contract_relation(
    ewhere: str, edge: dict, exports: dict[str, set[str]]
) -> None:
    """A `CONTRACT_CONSUMES` edge names a contract its own producer exports."""
    require(ewhere, edge, {"contract"})
    # Exported by THIS edge's `from`, not by some unit somewhere. The previous check
    # ran only under `sealed` and compared against the union of every unit's exports,
    # so a seal could name a contract an unrelated unit published — a relation
    # between two units justified by a third.
    if edge["contract"] not in exports.get(edge["from"], set()):
        raise ManifestError(
            f"{ewhere}: CONTRACT_CONSUMES names contract {edge['contract']!r}, "
            f"which {edge['from']!r} does not export. A contract edge is a relation "
            f"to the PRODUCER's published interface; if this dependency is real but "
            f"no such contract exists, it is a COMPILE_DEPENDENCY."
        )


def _validate_seal(ewhere: str, edge: dict) -> None:
    """Only a contract edge may be sealed, and a seal says who sealed it and why."""
    if edge["kind"] != "CONTRACT_CONSUMES":
        raise ManifestError(
            f"{ewhere}: only a CONTRACT_CONSUMES edge may be sealed. Sealing "
            f"means source-only dirtiness stops at a proved unchanged contract, "
            f"which is meaningless without a contract."
        )
    require(ewhere, edge, {"sealed_by", "rationale"})
