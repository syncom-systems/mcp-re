# SPDX-License-Identifier: Apache-2.0
"""The consumer's half of a contract relation is derived from the graph's edges and is not an authored unit field."""

from __future__ import annotations

from pathlib import Path

from _manifest import load_verification
from _measured_inputs_support import (
    DOC,
    UNITS,
    measure,
)


# --- the consumer's half of a contract relation --------------------------------
#
# `consumed_contracts` was an independently authored unit field that no unit declared, beside
# nine `CONTRACT_CONSUMES` edges that named no contract, beside a third empty copy in every
# attestation. Three representations that had never had to agree. It is now derived from the
# edges, and these are the controls that say so.

CONTRACT = "contract://core/time/parse_rfc3339_utc"
PRODUCER = "core.time_rfc3339"
CONSUMER = "core.verification_taxonomy"


def _doc_with(edge: dict) -> dict:
    """The real manifest plus one edge. Everything else the encoding reads is unchanged, so
    a moved fingerprint is attributable to the edge and to nothing else."""
    return {**DOC, "edge": [*DOC.get("edge", []), edge]}


def _contract_edge(to: str) -> dict:
    return {"kind": "CONTRACT_CONSUMES", "from": PRODUCER, "to": to, "contract": CONTRACT}


def test_the_consumed_contracts_component_is_derived_and_not_authored():
    """The unit key is gone, so there is nothing to author. The component still exists and
    still participates — it is now a reading of the graph rather than a second claim about
    it."""
    from _manifest import ManifestError, _UNIT_KEYS
    from _record_rules import reject_unknown

    assert "consumed_contracts" not in _UNIT_KEYS
    try:
        reject_unknown("t", {"consumed_contracts": []}, _UNIT_KEYS)
    except ManifestError as exc:
        assert "[[edge]].contract" in str(exc), exc
    else:
        raise AssertionError("a unit was allowed to declare what it consumes twice")


def test_an_incoming_contract_edge_moves_the_consumer():
    """The property the authored field could not have: a change in WHICH producer contract a
    unit consumes changes the consumer's identity, without anyone editing the consumer."""
    unit = UNITS[CONSUMER]
    before = measure(unit)
    after = measure(unit, doc=_doc_with(_contract_edge(CONSUMER)))
    assert before["components"]["consumed_contracts"] == []
    assert after["components"]["consumed_contracts"] == [CONTRACT]
    assert before["fingerprint"] != after["fingerprint"]


def test_the_producer_is_not_moved_by_the_consumer_choosing_it():
    """The other half of the relation stays the producer's. `exported_contracts` is what the
    producer published; who consumes it is not a fact about the producer, and a fingerprint
    that moved here would invalidate a proof because someone else started depending on it."""
    producer = UNITS[PRODUCER]
    before = measure(producer)["fingerprint"]
    after = measure(producer, doc=_doc_with(_contract_edge(CONSUMER)))["fingerprint"]
    assert before == after


def test_a_contract_edge_into_another_unit_does_not_move_this_one():
    """The negative direction, and the one a derivation keyed on the wrong endpoint would
    fail: it is the edges that arrive HERE, not every contract edge in the graph."""
    unit = UNITS[CONSUMER]
    before = measure(unit)["fingerprint"]
    elsewhere = _doc_with(_contract_edge("core.verification_error_taxonomy"))
    after = measure(unit, doc=elsewhere)["fingerprint"]
    assert before == after


def test_a_non_contract_edge_into_this_unit_does_not_move_it():
    """A `COMPILE_DEPENDENCY` is a real dependency and is not a consumed contract. If this
    moved, the component would be measuring the dependency graph rather than the contract
    relation, and the nine retyped edges would have re-entered it through the back door."""
    unit = UNITS[CONSUMER]
    before = measure(unit)["fingerprint"]
    plain = _doc_with({"kind": "COMPILE_DEPENDENCY", "from": PRODUCER, "to": CONSUMER})
    after = measure(unit, doc=plain)["fingerprint"]
    assert before == after


def _while_manifest_has(edge_toml: str, observe):
    """Append one `[[edge]]` block to the REAL manifest, observe INSIDE the window, restore."""
    from _manifest import VERIFICATION_TOML

    path = Path(VERIFICATION_TOML)
    original = path.read_bytes()
    try:
        path.write_bytes(original + edge_toml.encode("utf-8"))
        return observe()
    finally:
        path.write_bytes(original)


def test_the_derivation_reads_the_graph_direction_the_graph_declares():
    """Through the production loader, and on the axis that is easy to get backwards.

    `propagate` states the direction: `from` PRODUCES, `to` CONSUMES. So a unit's consumed
    contracts are the contracts on the edges arriving AT it, and the contract on each is the
    one its `from` exports — which admission has already made a checked fact rather than a
    convention. A derivation keyed on `from` would be internally consistent and would report
    the producer as consuming its own contract.
    """
    from _manifest import load_verification

    def observe():
        doc = load_verification()
        units = {u["id"]: u for u in doc["unit"]}
        consumer = measure(units[CONSUMER], doc=doc)["components"]["consumed_contracts"]
        producer = measure(units[PRODUCER], doc=doc)["components"]["consumed_contracts"]
        return consumer, producer, units[PRODUCER].get("exported_contracts", [])

    consumer, producer, exported = _while_manifest_has(
        f'''
[[edge]]
kind = "CONTRACT_CONSUMES"
from = "{PRODUCER}"
to = "{CONSUMER}"
contract = "{CONTRACT}"
''',
        observe,
    )
    # The consumer is the edge's `to`, and what it consumes is what the `from` EXPORTS.
    assert consumer == [CONTRACT], consumer
    assert CONTRACT in exported, exported
    # And the producer consumes nothing by producing.
    assert producer == [], producer
