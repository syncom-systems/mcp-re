# SPDX-License-Identifier: Apache-2.0
"""Cases for root completeness.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _assumptions import (
    load_assumptions,
)
from _fingerprint import (
    assumption_digest,
)
from _manifest import (
    load_verification,
)
from _review import (
    COMPLETE,
    INCOMPLETE,
    UNDECLARED,
    closure_satisfied,
    load_reviews,
    root_completeness,
)
from _theorem_review_support import (
    assurance,
    registry,
    rooted,
    theorem,
)


def test_an_undeclared_root_set_is_never_a_pass():
    """The emptiest registry must not be the greenest. Nothing is claimed at the boundary,
    so nothing about the boundary is established — and closure mode refuses it too."""
    result = rooted(theorem(), roots=[])
    assert result["verdict"] == UNDECLARED, result
    assert closure_satisfied(result) is False


def test_a_ratified_root_with_no_support_closure_is_a_gap_not_a_pass():
    """Control 3. The claim is stated, its owner is real, and the evidence does not exist.
    That is the §28.5 GAP terminal, and it is DERIVED — there is no status field to set."""
    result = rooted(theorem(supported_by=[]), roots=["THM-0001"])
    assert result["verdict"] == INCOMPLETE, result
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes and causes[0].startswith("GAP:"), causes


def test_evidence_stays_pass_while_root_completeness_reports_incomplete():
    """Control 4, the load-bearing one. THM-0001 is established on fresh evidence and a
    current review; the ratified root above it rests on a premise that has none. Ordinary
    verification has nothing to complain about, and the system argument is still open."""
    leaf = theorem(id="THM-0001")
    missing = theorem(id="THM-0002", supported_by=[])
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    doc = registry(leaf, missing, root, roots=["THM-0003"])
    states = assurance(doc)
    assert states["THM-0001"]["currently_verified"] is True
    result = root_completeness(doc, states)
    assert result["verdict"] == INCOMPLETE
    blocking = {row["theorem"]: row["cause"] for row in result["blocking"]["THM-0003"]}
    # The report names the node that actually blocks it, not only the root.
    assert blocking["THM-0002"].startswith("GAP:"), blocking
    assert blocking["THM-0003"].startswith("DEPENDENCY:"), blocking
    assert "THM-0001" not in blocking


def test_closure_mode_refuses_exactly_that_case():
    """Control 5. The same tree that ordinary CI passes is what T6 and release assurance
    must fail on."""
    leaf = theorem(id="THM-0001")
    missing = theorem(id="THM-0002", supported_by=[])
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    result = rooted(leaf, missing, root, roots=["THM-0003"])
    assert closure_satisfied(result) is False


def test_completeness_becomes_pass_once_the_missing_support_is_established():
    """Control 6, paired with 3-5 so the refusal above is not vacuous: the identical shape
    with the gap closed reports COMPLETE and satisfies closure mode."""
    leaf = theorem(id="THM-0001")
    filled = theorem(id="THM-0002")
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    result = rooted(leaf, filled, root, roots=["THM-0003"])
    assert result["verdict"] == COMPLETE, result
    assert result["blocking"] == {}
    assert closure_satisfied(result) is True


def test_a_dirty_unit_under_a_root_is_evidence_not_a_gap():
    """A stale lane and a missing architecture are different findings with different
    remedies. Reporting both as GAP would send a reviewer looking for a component that
    exists."""
    result = rooted(theorem(), roots=["THM-0001"], unit_state="DIRTY_SELF")
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes[0].startswith("EVIDENCE:"), causes


def test_an_unreviewed_root_is_reported_as_review_not_gap():
    result = rooted(theorem(), roots=["THM-0001"], reviewed=False)
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes[0].startswith("SPECIFICATION REVIEW UNREVIEWED"), causes


# --- the repository as it stands -----------------------------------------------------


def test_the_live_review_store_is_wellformed_and_empty():
    """No theorem is declared, so no review record may exist. A record for a theorem that
    does not exist would be an approval of nothing, sitting in the tree looking valid."""
    from _manifest import REPO_ROOT
    from _review import review_root
    from _theorems import load_theorems

    doc = load_verification()
    theorems = load_theorems({unit["id"] for unit in doc.get("unit", [])})
    declared = {row["id"] for row in theorems.get("theorem", [])}
    for (axis, subject), _record in load_reviews(review_root(REPO_ROOT)).items():
        if axis == "specification":
            assert subject in declared, f"review for undeclared theorem {subject}"


def test_the_assumption_axis_reads_the_live_registry_entry():
    """The assumption axis keys on the entry's content digest, so widening a justification
    invalidates its review exactly as weakening a statement invalidates a specification."""
    entries = load_assumptions().get("assumption", [])
    assert entries, "the pilot registered assumptions; this test needs one"
    entry = dict(entries[0])
    before = assumption_digest(entry)
    entry["justification"] = entry["justification"] + " And another thing."
    assert assumption_digest(entry) != before
