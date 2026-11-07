# SPDX-License-Identifier: Apache-2.0
"""Cases for the claim and fingerprint axes.

Cases for `test_theorem_review.py`, which runs them.
"""

from __future__ import annotations

from _assumptions import (
    load_assumptions,
)
from _fingerprint import (
    fingerprint_unit,
)
from _manifest import (
    load_verification,
)
from _review import (
    CAUSE_PRECEDENCE,
    COMPONENT_CAUSE,
    REVIEWED,
    REVIEW_STATES,
    _by_precedence,
    derive_review_state,
)
from _theorem_review_support import (
    UNIT,
    fingerprints,
    premise_chain,
    registry,
    review_for,
    theorem,
)
from _toolchain_lock import (
    load_toolchains,
)


# --- THE control ---------------------------------------------------------------


def test_the_reported_cause_is_a_decision_not_an_alphabet():
    """Several components can move at once, and the reviewer is told ONE cause. Which one
    was `sorted(causes)[0]` — alphabetical order, which happened to put `STALE_CLAIM` first.

    Correct by accident is not correct: the next cause added ranks itself by its spelling,
    and a `STALE_A…` would mask a moved claim behind it. Both halves are asserted here —
    that the ranking holds, and that ALPHABETICAL ORDER IS NOT THE MECHANISM, which is the
    half a green tree cannot show."""
    # The ranking itself, over the real causes.
    assert _by_precedence({"STALE_CLAIM", "STALE_REVIEW_REQUIREMENT"}) == "STALE_CLAIM"
    assert (
        _by_precedence({"STALE_DEPENDENCY_CLAIM", "STALE_REVIEW_REQUIREMENT"})
        == "STALE_DEPENDENCY_CLAIM"
    )
    # A component this schema cannot name leads, mirroring UNKNOWN in `_graph`: the named
    # causes cannot be assumed complete when an unnamed one moved.
    assert _by_precedence({"STALE_CLAIM", "STALE_INPUT"}) == "STALE_INPUT"

    # The falsifier. Under the old rule this returned the alphabetically first name; under
    # the precedence it returns the RANKED one, and the two disagree by construction.
    invented = "STALE_AAA_WOULD_HAVE_WON_ALPHABETICALLY"
    assert sorted({"STALE_CLAIM", invented})[0] == invented
    assert _by_precedence({"STALE_CLAIM", invented}) == "STALE_CLAIM"
    # An unranked cause sorts LAST, so it can never silently outrank a placed one.
    assert _by_precedence({invented}) == invented

    # And the ranking covers exactly the causes a moved COMPONENT can produce, so none
    # reaches the fallback by omission. `STALE_REVIEW` is deliberately outside it: that is
    # what a record carrying no components yields, which is not a statement about which
    # component moved and has no place in an ordering of those.
    producible = set(COMPONENT_CAUSE.values()) | {"STALE_INPUT"}
    assert set(CAUSE_PRECEDENCE) == producible, (
        set(CAUSE_PRECEDENCE) ^ producible
    )
    assert producible <= REVIEW_STATES
    assert "STALE_REVIEW" not in CAUSE_PRECEDENCE


def test_two_components_moving_reports_the_more_fundamental_one():
    """The same property end to end, through `derive_review_state` rather than the helper:
    a theorem whose claim AND whose review requirement both moved is STALE_CLAIM, because
    the claim has to be re-read either way."""
    strong = registry()
    before = fingerprints(strong)["THM-0001"]
    record = review_for(before)
    assert derive_review_state(before, record)[0] == REVIEWED

    moved = registry(
        theorem(
            statement="Every NORMAL admitted request satisfies the skew-widened window "
            "constraints.",
            review_requirement="Owner security-specification review",
        )
    )
    after = fingerprints(moved)["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_CLAIM", (state, reason)
    assert "theorem_claim" in reason


def test_weakening_a_statement_dirties_specification_review():
    """`all accepted transitions` → `all NORMAL accepted transitions`, §14.7's own example.

    No source moved, so every prover stays green. The claim moved, so the approval no longer
    covers what is written — and nobody had to remember a rule for that to happen."""
    strong = registry()
    before = fingerprints(strong)["THM-0001"]
    record = review_for(before)
    assert derive_review_state(before, record)[0] == REVIEWED

    weak = registry(
        theorem(
            statement="Every NORMAL admitted request satisfies the skew-widened window "
            "constraints."
        )
    )
    after = fingerprints(weak)["THM-0001"]

    state, reason = derive_review_state(after, record)
    assert state == "STALE_CLAIM", (state, reason)
    assert "theorem_claim" in reason


def test_the_prover_stays_green_while_the_specification_goes_dirty():
    """The other half of the same control, and the one that makes it meaningful.

    If restating a claim also moved the UNIT fingerprint, the prover would go dirty too and
    the test above would prove nothing about the separation of axes — it would just be a
    global invalidation."""
    doc = load_verification()
    unit = next(row for row in doc["unit"] if row["id"] == UNIT)
    toolchains, assumptions = load_toolchains(), load_assumptions()

    before = fingerprint_unit(unit, doc, toolchains, assumptions)
    # Restate the theorem — the registry is a different file entirely.
    _ = fingerprints(registry(theorem(statement="something else entirely")))
    after = fingerprint_unit(unit, doc, toolchains, assumptions)

    assert before["fingerprint"] == after["fingerprint"]
    assert "theorem_claim" not in after["components"]


def test_a_source_change_does_not_move_the_claim_fingerprint():
    """The claim fingerprint is the claim surface alone — what the correction chain and the
    claim-surface gate are about. Supporting source reaches the review through the separate
    semantic `review_digest` (tested below), never through this digest: folding it in here
    would make every code edit read as a change to what the theorem SAYS."""
    current = fingerprints(registry())["THM-0001"]
    assert set(current["components"]) == {
        "encoding_version",
        "theorem_id",
        "theorem_claim",
        "theorem_dependencies",
        "theorem_review_requirement",
    }


# --- what else must move the claim ----------------------------------------------


def test_widening_scope_dirties_review():
    """`scope` is where a claim says what it does NOT establish. Widening it silently is how
    an over-read enters a document that still reads as reviewed."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(scope="Everything about admission.")))["THM-0001"]
    assert derive_review_state(after, record)[0] == "STALE_CLAIM"


def test_relaxing_the_review_requirement_dirties_review():
    """An approval given under owner review is not an approval under 'any review'."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(review_requirement="Any reviewer")))["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_REVIEW_REQUIREMENT", (state, reason)


def test_renaming_a_theorem_does_not_dirty_review():
    """`title` is a label, not the proposition. If renaming invalidated approvals, the
    registry would punish the one edit that costs nothing to make."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(title="A clearer name for the same claim")))[
        "THM-0001"
    ]
    assert derive_review_state(after, record)[0] == REVIEWED


def test_weakening_a_premise_dirties_every_claim_above_it():
    """Transitive, not just direct. A claim rests on everything underneath it, so a premise
    rewritten two levels down must reach the top — otherwise the composition is a badge."""
    before = fingerprints(premise_chain("The strong premise."))
    records = {tid: review_for(fp, tid) for tid, fp in before.items()}
    after = fingerprints(premise_chain("A much weaker premise."))

    assert derive_review_state(after["THM-0001"], records["THM-0001"])[0] == "STALE_CLAIM"
    for dependent in ("THM-0002", "THM-0003"):
        state, reason = derive_review_state(after[dependent], records[dependent])
        assert state == "STALE_DEPENDENCY_CLAIM", (dependent, state, reason)
        assert "theorem_dependencies" in reason


def test_adding_a_dependency_dirties_the_dependent():
    before = fingerprints(registry(theorem(id="THM-0001"), theorem(id="THM-0002")))
    record = review_for(before["THM-0002"], "THM-0002")
    after = fingerprints(
        registry(theorem(id="THM-0001"), theorem(id="THM-0002", depends_on=["THM-0001"]))
    )
    assert derive_review_state(after["THM-0002"], record)[0] == "STALE_DEPENDENCY_CLAIM"


def test_a_sibling_theorem_over_the_same_unit_is_untouched():
    """Several theorems share one supporting unit. Restating one must not dirty the others,
    or the layer's whole benefit — separating claims that a single prover run supports —
    disappears into one shared status."""
    before = fingerprints(registry(theorem(id="THM-0001"), theorem(id="THM-0002")))
    record = review_for(before["THM-0002"], "THM-0002")
    after = fingerprints(
        registry(theorem(id="THM-0001", statement="Restated."), theorem(id="THM-0002"))
    )
    assert derive_review_state(after["THM-0002"], record)[0] == REVIEWED
