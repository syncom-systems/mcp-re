# SPDX-License-Identifier: Apache-2.0
"""Cases for review-record parsing.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _review import (
    REVIEWED,
    REVIEW_STATES,
    _valid,
    derive_review_state,
)
from _theorem_review_support import (
    fingerprints,
    registry,
    review_for,
    theorem,
)


def test_a_record_carrying_an_approval_bit_is_dropped():
    """§14.7: no mutable approval string. A record that says `approved: true` alongside a
    fingerprint is the stored status field wearing the record's clothes.

    Refused by the CLOSED schema rather than by a list of bad names — that is the stronger
    rule, since it also refuses the approval bit nobody thought to name. The named-key scan
    over arbitrary documents is `scripts/registry_approval_gate.py`."""
    current = fingerprints(registry())["THM-0001"]
    for key in ("approved", "status", "verdict", "signed_off", "anything_else"):
        assert _valid(review_for(current) | {key: True}) is None, key
    # And the schema is closed in the direction that matters: dropping a REQUIRED key is
    # equally fatal, so a record cannot approve without naming who reviewed or what.
    for key in ("reviewer", "reviewed_fingerprint", "subject", "axis"):
        record = review_for(current)
        del record[key]
        assert _valid(record) is None, key


def test_a_record_for_the_wrong_axis_is_dropped():
    current = fingerprints(registry())["THM-0001"]
    assert _valid(review_for(current) | {"axis": "assumption"}) is None
    assert _valid(review_for(current) | {"axis": "vibes"}) is None


def test_a_record_with_no_reviewer_is_dropped():
    current = fingerprints(registry())["THM-0001"]
    assert _valid(review_for(current) | {"reviewer": "  "}) is None


def test_a_record_predating_the_current_components_is_unknown_not_reviewed():
    """The `_graph` rule, restated on this axis: a record that cannot be compared says
    nothing, and saying nothing is not approval."""
    current = fingerprints(registry())["THM-0001"]
    stale_schema = review_for(current)
    stale_schema["components"] = {"theorem_claim": current["components"]["theorem_claim"]}
    state, reason = derive_review_state(current, stale_schema)
    assert state == "UNKNOWN" and "predates" in reason


def test_matching_components_with_a_different_digest_is_unknown():
    """Components equal, aggregate different ⇒ the encoding changed, so the comparison
    means something else. Preserved from the unit engine deliberately."""
    current = fingerprints(registry())["THM-0001"]
    record = review_for(current)
    record["reviewed_fingerprint"] = "sha256:" + "0" * 64
    state, reason = derive_review_state(current, record)
    assert state == "UNKNOWN" and "encoding" in reason


def test_a_componentless_record_still_detects_staleness():
    current = fingerprints(registry())["THM-0001"]
    record = review_for(current)
    del record["components"]
    assert derive_review_state(current, record)[0] == REVIEWED
    after = fingerprints(registry(theorem(statement="Restated.")))["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_REVIEW" and "no components" in reason


def test_every_returned_state_is_in_the_closed_set():
    """A state nobody enumerated is a state no consumer handles, and an unhandled state in a
    conjunction is how a not-reviewed subject slips through as truthy."""
    current = fingerprints(registry())["THM-0001"]
    seen = {
        derive_review_state(current, None)[0],
        derive_review_state(current, review_for(current))[0],
    }
    assert seen <= REVIEW_STATES
