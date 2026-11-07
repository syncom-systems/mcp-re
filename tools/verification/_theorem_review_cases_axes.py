# SPDX-License-Identifier: Apache-2.0
"""Cases for the two review axes.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _assumptions import (
    load_assumptions,
)
from _fingerprint import (
    EVIDENCE_UNIT_COMPONENTS,
    SEMANTIC_UNIT_COMPONENTS,
    Registries,
    assumption_digest,
    fingerprint_unit,
)
from _manifest import (
    load_verification,
)
from _review import (
    NO_SEMANTIC_DIGEST,
    REVIEWED,
    STALE_SEMANTICS,
    Basis,
    _valid,
    theorem_assurance,
)
from _theorem_review_support import (
    ASM,
    BACKED,
    UNIT,
    UNIT_FP,
    attested,
    fingerprints,
    no_premises,
    registry,
    review_for,
    semantics,
    theorem,
    two_axis,
    unit_fp,
)
from _toolchain_lock import (
    load_toolchains,
)


def test_both_axes_current_is_currently_verified():
    state = two_axis()
    assert state["review_current"] and state["evidence_established"], state
    assert state["currently_verified"] is True


def test_a_claim_change_is_not_review_current():
    state = two_axis(now_doc=registry(theorem(statement="Some admitted requests are fresh.")))
    assert state["review_current"] is False
    assert state["review"][0] == "STALE_CLAIM", state["review"]
    assert state["currently_verified"] is False


def test_a_premise_change_is_not_review_current():
    """The new premise text is itself reviewed and backed — the THEOREM was still read over
    the old one, so its review is not current."""
    old = {"THM-0001": {"ASM-0001": assumption_digest(ASM)}}
    widened = {**ASM, "description": ASM["description"] + " Or nearly so."}
    new = {"THM-0001": {"ASM-0001": assumption_digest(widened)}}
    state = two_axis(read_premises=old, now_premises=new)
    assert state["premise_review"]["ASM-0001"][0] == REVIEWED
    assert state["review_current"] is False
    assert state["review"][0] == STALE_SEMANTICS, state["review"]
    assert "premise ASM-0001" in state["review"][1]


def test_an_implementation_semantics_change_is_not_review_current():
    """The case Ruling 34 §7 C found: the claim text stands still while the code it is about
    changes. The evidence can be re-run green; the review is still of other code."""
    moved = unit_fp(source_inputs={"src/freshness.rs": "sha256:ccc"})
    state = two_axis(now_units={UNIT: moved})
    assert state["review_current"] is False
    assert state["review"][0] == STALE_SEMANTICS, state["review"]
    assert "source_inputs" in state["review"][1]
    assert state["evidence_established"] is True  # a fresh run over the new code
    assert state["currently_verified"] is False


def test_a_material_test_selection_change_is_not_review_current():
    narrowed = unit_fp(test_selection={"symbols": []})
    state = two_axis(now_units={UNIT: narrowed})
    assert state["review_current"] is False
    assert "test_selection" in state["review"][1]


def test_a_proved_symbol_change_is_not_review_current():
    state = two_axis(now_units={UNIT: unit_fp(proved_symbols=[])})
    assert state["review_current"] is False
    assert "proved_symbols" in state["review"][1]


def test_a_toolchain_change_leaves_review_current_and_evidence_stale():
    """A Verus or Lean version bump with identical semantic inputs: the run must be repeated,
    and the owner has nothing new to read."""
    from _graph import derive_unit_state

    bumped = unit_fp(toolchain_identity={"verus": "0.2026.10.01"})
    unit_state, _ = derive_unit_state(UNIT, bumped, attested(UNIT_FP))
    assert unit_state == "DIRTY_TOOLCHAIN"
    state = two_axis(now_units={UNIT: bumped}, unit_state=unit_state)
    assert state["review_current"] is True, state["review"]
    assert state["evidence_established"] is False
    assert state["currently_verified"] is False


def test_a_proof_policy_change_stales_evidence_until_re_established():
    from _graph import derive_unit_state

    for moved in (
        unit_fp(review_policy_revision="policy-8"),
        unit_fp(verus_lane_identity={"tools/verification/verify-verus": "sha256:ddd"}),
    ):
        stale, _ = derive_unit_state(UNIT, moved, attested(UNIT_FP))
        assert stale != "FRESH"
        before = two_axis(now_units={UNIT: moved}, unit_state=stale)
        assert before["review_current"] is True
        assert before["evidence_established"] is False
        # Re-run under the new policy: an attestation at the new full fingerprint.
        fresh, _ = derive_unit_state(UNIT, moved, attested(moved))
        assert fresh == "FRESH"
        after = two_axis(now_units={UNIT: moved}, unit_state=fresh)
        assert after["currently_verified"] is True


def test_neither_half_alone_is_currently_verified():
    only_review = two_axis(unit_state="UNKNOWN")
    assert only_review["review_current"] and not only_review["evidence_established"]
    assert only_review["currently_verified"] is False
    only_evidence = two_axis(now_units={UNIT: unit_fp(source_inputs={"x.rs": "sha256:1"})})
    assert only_evidence["evidence_established"] and not only_evidence["review_current"]
    assert only_evidence["currently_verified"] is False


def test_a_review_without_a_semantic_digest_is_never_current():
    """Records written before the semantic axis name no supporting evidence. No digest is
    reconstructed for them."""
    doc = registry()
    fps = fingerprints(doc)
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"])}
    state = theorem_assurance(
        doc,
        Basis(
            fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), BACKED,
            semantics(doc, no_premises(doc)),
        ),
    )["THM-0001"]
    assert state["specification_review"][0] == REVIEWED
    assert state["review"][0] == NO_SEMANTIC_DIGEST
    assert state["currently_verified"] is False


def test_an_uncomputable_semantic_digest_is_not_current():
    """A supporting unit with no fingerprint gives no digest, and nothing is current against
    no digest."""
    state = two_axis(now_units={"some.other_unit": UNIT_FP})
    assert state["review_current"] is False
    assert state["review"][0] == "UNKNOWN", state["review"]


def test_a_semantic_digest_on_a_non_specification_record_is_dropped():
    record = {
        "axis": "assumption",
        "subject": "ASM-0001",
        "reviewed_fingerprint": "sha256:" + "0" * 64,
        "review_digest": "sha256:" + "0" * 64,
        "reviewer": "owner@example.com",
    }
    assert _valid(record) is None


def test_every_unit_component_is_placed_on_exactly_one_axis():
    """The partition is closed. An unplaced component is treated as semantic, so forgetting
    one costs a re-read rather than a false current review — but it must still be placed,
    and this census over every live unit fingerprint and every component the freshness
    engine classifies is what makes it so."""
    from _graph import COMPONENT_STATE, STRUCTURAL_COMPONENT, UNRESOLVED_COMPONENT

    assert not SEMANTIC_UNIT_COMPONENTS & EVIDENCE_UNIT_COMPONENTS
    placed = SEMANTIC_UNIT_COMPONENTS | EVIDENCE_UNIT_COMPONENTS
    known = set(COMPONENT_STATE) | set(STRUCTURAL_COMPONENT) | set(UNRESOLVED_COMPONENT)
    assert known <= placed, sorted(known - placed)
    doc = load_verification()
    registries = Registries(doc, load_toolchains(), load_assumptions())
    produced = set()
    for unit in doc["unit"]:
        produced |= set(fingerprint_unit(unit, registries)["components"])
    assert produced <= placed, sorted(produced - placed)
    assert placed <= produced | known, sorted(placed - produced - known)


def test_the_toolchain_is_not_semantic_and_the_source_is():
    """Pins the two placements Ruling 35 §3 names, so a reshuffle of the sets that swapped
    them would fail here even if the census still balanced."""
    for name in ("toolchain_identity", "review_policy_revision", "verus_lane_identity",
                 "lean_lane_identity", "generated_inputs", "build_configuration"):
        assert name in EVIDENCE_UNIT_COMPONENTS, name
    for name in ("source_inputs", "test_selection", "test_sources", "mutation_probes",
                 "proved_symbols", "lean_theorem_sources", "trusted_assumptions"):
        assert name in SEMANTIC_UNIT_COMPONENTS, name
