# SPDX-License-Identifier: Apache-2.0
"""The Verus lane's instruments are part of the identity of exactly the units that claim a proof."""

from __future__ import annotations

from _fingerprint import VERUS_LANE_INPUTS
from _measured_inputs_support import (
    DOC,
    UNITS,
    components,
    measure,
    while_perturbed,
)


# --- the seventh lane: what decides that a PROOF was checked ---------------------
#
# Six of the seven formal lanes carried their instrument in the consumer's identity and the
# `verus` lane did not. Measured before the repair by perturbing one file and re-deriving all
# 244 fingerprints: `verify-tests` moved 227, `verify-verus` moved 0, `_verus_results.py`
# moved 0. So a standing `verus: pass` stayed FRESH under an identity that no longer described
# how it was earned. These are the controls that say it cannot any more.

VERUS_UNIT = "core.time_rfc3339"


def _verus_units() -> list[str]:
    from _lanes import claims

    return sorted(uid for uid, u in UNITS.items() if claims(u, "verus"))


def test_the_verus_population_is_the_repositorys_machine_checked_surface():
    """A component whose population nobody measured can be empty and look enforced. This one
    reaches exactly the units that claim a proof — the same six that declare
    `proved_symbols`, export a `contract://` and carry class V1."""
    claimants = _verus_units()
    assert len(claimants) == 6, claimants
    assert claimants == sorted(u["id"] for u in DOC["unit"] if u.get("proved_symbols"))
    assert claimants == sorted(u["id"] for u in DOC["unit"] if u["class"] == "V1")
    for uid in claimants:
        identity = components(uid).get("verus_lane_identity")
        assert identity, (uid, identity)
        assert set(identity) == set(VERUS_LANE_INPUTS), (uid, sorted(identity))


def test_a_unit_without_verus_evidence_carries_no_verus_identity_key_at_all():
    """Not an empty one. A key present-and-empty on 238 units would have moved every one of
    them to record the absence of a thing they never had."""
    assert "verus_lane_identity" not in components("proxy.certificate_identity")


def test_editing_the_verus_lane_moves_exactly_the_proved_units():
    """Both directions in one measurement: the six move, and nothing else does."""
    claimants = set(_verus_units())
    before = {
        uid: measure(u)["fingerprint"]
        for uid, u in UNITS.items()
    }

    def observe():
        return {
            uid: measure(u)["fingerprint"]
            for uid, u in UNITS.items()
        }

    for instrument in (
        "tools/verification/verify-verus",
        "tools/verification/_verus_results.py",
    ):
        after = while_perturbed(instrument, observe)
        moved = {uid for uid in before if before[uid] != after[uid]}
        assert moved == claimants, (instrument, sorted(moved ^ claimants))


def test_the_target_table_module_moves_every_lane_that_resolves_a_label_through_it():
    """r12 Ruling 39 §8. The package a crate root is filed under selects the Verus target a
    proved unit is verified by, and the build-graph row a probe's red control runs in. Both
    lanes resolve through `_rust_targets`, so an edit there must move every unit whose
    evidence either lane establishes — not only the test lane's."""
    from _lanes import claims

    watched = set(_verus_units()) | {
        uid for uid, u in UNITS.items() if claims(u, "mutation")
    }
    assert len(watched) > len(_verus_units()), "no mutation claimant: the population is empty"
    before = {uid: measure(UNITS[uid])["fingerprint"]
              for uid in watched}

    def observe():
        return {uid: measure(UNITS[uid])["fingerprint"]
                for uid in watched}

    after = while_perturbed("tools/verification/_rust_targets.py", observe)
    unmoved = sorted(uid for uid in watched if before[uid] == after[uid])
    assert not unmoved, unmoved


def test_the_nonvacuity_adjudicator_moves_exactly_the_proved_units():
    claimants = set(_verus_units())
    before = {uid: measure(u)["fingerprint"]
              for uid, u in UNITS.items()}

    def observe():
        return {uid: measure(u)["fingerprint"]
                for uid, u in UNITS.items()}

    after = while_perturbed("tools/verification/_verus_nonvacuity.py", observe)
    moved = {uid for uid in before if before[uid] != after[uid]}
    assert moved == claimants, sorted(moved ^ claimants)


def test_a_verification_file_in_no_lane_does_not_move_the_proved_units():
    """The negative control. If this moved them, the component would be digesting the
    directory rather than the instrument, and the criterion would be `is reachable` rather
    than `decides the verdict`."""
    claimants = set(_verus_units())
    before = {uid: measure(UNITS[uid])["fingerprint"]
              for uid in claimants}

    def observe():
        return {uid: measure(UNITS[uid])["fingerprint"]
                for uid in claimants}

    after = while_perturbed("tools/verification/_review.py", observe)
    assert after == before


def test_a_fresh_proved_unit_stops_being_fresh_when_its_judge_changes():
    """The end-to-end case, and the one that would have caught this defect.

    Every other lane-identity control stops at the fingerprint. This one closes the loop the
    defect actually travelled: instrument -> STORED RECORD -> derived state. Attest one of the
    six at its current components, change `verify-verus` without rerunning the prover, and ask
    the engine what the unit is now.
    """
    from _graph import Attestation, derive_unit_state

    unit = UNITS[VERUS_UNIT]
    established = measure(unit)
    record = Attestation(
        unit_id=VERUS_UNIT,
        fingerprint=established["fingerprint"],
        components=established["components"],
        evidence={"verus": "pass"},
    )
    state, _ = derive_unit_state(VERUS_UNIT, established, {VERUS_UNIT: record})
    assert state == "FRESH", "the control measures nothing unless it starts from FRESH"

    def observe():
        now = measure(unit)
        return derive_unit_state(VERUS_UNIT, now, {VERUS_UNIT: record})

    state, reason = while_perturbed("tools/verification/verify-verus", observe)
    assert state == "DIRTY_EVIDENCE", (state, reason)
    assert "verus_lane_identity" in reason, reason


def test_the_verus_identity_does_not_touch_the_specification_axis():
    """A theorem's claim fingerprint reads `theorems.toml` and nothing else. An instrument
    repair that moved a claim would be spending an owner's signature on a tooling change."""
    from _theorems import load_theorems
    from _fingerprint import fingerprint_theorem

    registry = load_theorems(set(UNITS))

    def observe():
        return {e["id"]: fingerprint_theorem(e, registry)["fingerprint"]
                for e in registry["theorem"]}

    before = observe()
    after = while_perturbed("tools/verification/verify-verus", observe)
    assert after == before
