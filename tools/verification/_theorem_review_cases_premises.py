# SPDX-License-Identifier: Apache-2.0
"""Cases for premise review.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _review import (
    PREMISE_UNREVIEWED,
    REVIEWED,
    Basis,
    theorem_assurance,
)
from _theorem_review_support import (
    ASM,
    BACKED,
    UNIT,
    fingerprints,
    premise_assurance,
    registry,
    review_for,
    semantics,
)


def test_a_reviewed_claim_on_an_unreviewed_premise_is_not_reviewed():
    """The false REVIEWED the closure packet found: THM-0007 and 22 others read REVIEWED
    while an assumption under them changed and nobody signed it. The claim's own record is
    current; the premise has none."""
    state = premise_assurance(record=False)
    assert state["specification_review"][0] == REVIEWED
    assert state["review"][0] == PREMISE_UNREVIEWED, state["review"]
    assert state["currently_verified"] is False


def test_a_premise_reviewed_at_an_earlier_text_is_not_reviewed():
    """The digest is over the whole entry, so a widened premise invalidates its review."""
    widened = {**ASM, "description": ASM["description"] + " Or nearly so."}
    state = premise_assurance(premise_entry=widened)
    assert state["review"][0] == PREMISE_UNREVIEWED, state["review"]
    assert "ASM-0001" in state["review"][1]


def test_a_reviewed_and_backed_premise_lets_the_claim_be_reviewed():
    state = premise_assurance()
    assert state["review"][0] == REVIEWED, state["review"]
    assert state["currently_verified"] is True


def test_an_unknown_premise_closure_is_not_reviewed():
    """A theorem the caller computed no closure for has an UNKNOWN closure, not an empty
    one: no premises to check must not read as every premise checked."""
    doc = registry()
    fps = fingerprints(doc)
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"])}
    state = theorem_assurance(
        doc, Basis(fps, reviews, {UNIT: ("FRESH", "fixture")}, {}, BACKED, semantics(doc, {}))
    )["THM-0001"]
    assert state["review"][0] != REVIEWED, state["review"]
