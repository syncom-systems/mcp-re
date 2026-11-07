# SPDX-License-Identifier: Apache-2.0
"""Cases for establishment across all axes.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _review import (
    theorem_assurance,
)
from _theorem_review_support import (
    BACKED,
    UNIT,
    assurance,
    fingerprints,
    no_premises,
    premise_chain,
    registry,
    review_for,
    semantics,
    theorem,
)


def test_all_axes_green_is_established():
    assert assurance(registry())["THM-0001"]["currently_verified"] is True


def test_an_unreviewed_specification_is_not_established():
    """The case the whole phase is for: the prover is green, the unit is FRESH, and nobody
    has reviewed what is claimed."""
    assert assurance(registry(), reviewed=False)["THM-0001"]["currently_verified"] is False


def test_a_dirty_unit_is_not_established():
    for state in ("DIRTY_SELF", "DIRTY_ASSUMPTION", "UNKNOWN", "BLOCKED"):
        result = assurance(registry(), unit_state=state)
        assert result["THM-0001"]["currently_verified"] is False, state


def test_a_theorem_with_no_supporting_unit_is_not_established():
    assert assurance(registry(theorem(supported_by=[])))["THM-0001"]["currently_verified"] is False


def test_a_deprecated_theorem_is_not_established():
    doc = registry(theorem(id="THM-0001", replaced_by="THM-0002"), theorem(id="THM-0002"))
    assert assurance(doc)["THM-0001"]["currently_verified"] is False
    assert assurance(doc)["THM-0002"]["currently_verified"] is True


def test_an_unestablished_premise_denies_every_claim_above_it():
    doc = premise_chain("The premise.")
    fps = fingerprints(doc)
    # Everything reviewed and fresh EXCEPT the bottom premise's review.
    digests = semantics(doc, no_premises(doc))
    reviews = {
        ("specification", tid): review_for(fp, tid, digests[tid])
        for tid, fp in fps.items()
        if tid != "THM-0001"
    }
    result = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), BACKED, digests
    )
    assert [result[tid]["currently_verified"] for tid in ("THM-0001", "THM-0002", "THM-0003")] == [
        False,
        False,
        False,
    ]
