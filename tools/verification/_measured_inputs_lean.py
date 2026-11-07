# SPDX-License-Identifier: Apache-2.0
"""The Lean extraction lane's identity, instruments, theorem text and generated model: what moves a `lean://` unit's fingerprint and what must leave every other unit alone."""

from __future__ import annotations

from _measured_inputs_support import (
    UNITS,
    components,
    measure,
    while_perturbed,
    perturbed_fingerprints,
)


def test_the_extraction_lane_instruments_are_part_of_the_evidence_identity():
    """SF-011. Four lanes carried their runner in the fingerprint and the two extraction
    lanes carried nothing, so `verify-lean`, `check-generated` and the model predicate could
    be narrowed with no `lean://` unit deriving DIRTY.

    The set is the JUDGEMENT cone, not the import closure: `verify-lean` transitively
    imports fourteen modules and most decide nothing about the verdict. The criterion each
    entry passes is whether changing it can alter whether the lane reports valid Lean
    evidence, what theorem population was activated, or whether a run that elaborated
    nothing is accepted."""
    c = components("core.time_civil_from_days")
    assert set(c["lean_lane_identity"]) == {
        "tools/verification/verify-lean",
        "tools/verification/_lean_axioms.py",
        "tools/verification/_lean_query.py",
        "tools/verification/_lean_model.py",
        "tools/verification/_extraction_identity.py",
        "tools/verification/_manifest.py",
        "tools/verification/_record_rules.py",
        "tools/verification/_unit_rules.py",
        "tools/verification/_assumptions.py",
        "tools/verification/_toolchain_lock.py",
        # Which tiers the lane covers and which scheme claims it: the lane catalogue.
        "tools/verification/_lanes.py",
    }
    assert set(c["generated_model_lane_identity"]) == {
        "tools/verification/check-generated",
        "tools/verification/regenerate-lean",
        "tools/verification/_lean_model.py",
        "tools/verification/_extraction_identity.py",
        "tools/verification/_lanes.py",
    }
    assert all(d.startswith("sha256:") for d in c["lean_lane_identity"].values())
    assert all(d.startswith("sha256:") for d in c["generated_model_lane_identity"].values())
    # The probe is excluded BY THE CRITERION, not by topic: it runs only under
    # `--activation-probe`, which returns before any unit is looked at and writes no record.
    both = set(c["lean_lane_identity"]) | set(c["generated_model_lane_identity"])
    assert "tools/verification/_lean_probe.py" not in both


def test_a_unit_without_lean_evidence_carries_no_extraction_identity_key_at_all():
    """ABSENT, not empty — the `gate_controls` precedent rather than the four host lanes'.

    One unit declares `lean://` today. An always-present key would have moved the other 243
    fingerprints, dropping every standing attestation in the tree to record the absence of a
    thing none of those units has."""
    c = components("http_profile.keyid")
    assert "lean_lane_identity" not in c
    assert "generated_model_lane_identity" not in c
    carrying = [
        unit_id
        for unit_id in UNITS
        if "lean_lane_identity" in components(unit_id)
    ]
    assert carrying == ["core.time_civil_from_days"], carrying


def test_editing_a_lean_instrument_moves_the_lean_unit_and_nothing_else():
    """Both directions, which is the whole point: before this component existed, editing
    `_lean_model.py` moved ZERO fingerprints while editing `verify-tests` moved one on this
    same unit. Cohort O was its own witness — it edited two of these files and dirtied
    nothing."""
    watched = ["core.time_civil_from_days", "http_profile.keyid", "core.time_rfc3339"]
    before = {
        unit_id: measure(UNITS[unit_id])[
            "fingerprint"
        ]
        for unit_id in watched
    }

    for instrument in (
        "tools/verification/_lean_axioms.py",
        "tools/verification/_lean_query.py",
        "tools/verification/check-generated",
        "tools/verification/regenerate-lean",
    ):
        after = perturbed_fingerprints(instrument, watched)
        assert after["core.time_civil_from_days"] != before["core.time_civil_from_days"], (
            f"{instrument} decides what a lean record means and moved nothing"
        )
        for bystander in ("http_profile.keyid", "core.time_rfc3339"):
            assert after[bystander] == before[bystander], (
                f"{instrument} dirtied {bystander}, which asks no extraction lane for evidence"
            )

    # The control. A lane instrument this unit does not consult must not dirty it, or the
    # component is measuring "somebody edited the platform" rather than "this unit's
    # instrument changed".
    after = perturbed_fingerprints("tools/verification/_structural.py", watched)
    assert after["core.time_civil_from_days"] == before["core.time_civil_from_days"]


def test_the_theorem_text_is_measured_not_only_its_name():
    """P-b. `lean_theorems` is a list of NAMES, and a name outlives its own statement:

        theorem civil_from_days_total : True := trivial

    resolves under the declared name, reports an EMPTY axiom closure — inside the kernel
    baseline, therefore accepted — and left the standing PASS deriving FRESH. `lean_theorems`
    said WHAT is claimed; nothing measured the claim. Same defect encoding v4 repaired for
    tests, one level up.

    Derived from the lakefile, not listed: the build definition decides which modules
    elaborate, and it participates too because it decides what the set CONTAINS."""
    sources = components("core.time_civil_from_days")["lean_theorem_sources"]
    assert set(sources) == {
        "verification/lean/lakefile.toml",
        "verification/lean/theorems/CivilFromDays.lean",
    }, sources
    assert all(d.startswith("sha256:") for d in sources.values())
    # The machine-owned half is NOT here. It is the model the claim is about, not the claim,
    # and the lakefile keeps the two in separate source directories for that reason.
    assert not any(path.startswith("verification/lean/generated/") for path in sources)


def test_editing_the_theorem_text_moves_the_lean_unit():
    """Direction one. Before this component, the whole proof corpus could be rewritten
    without moving a fingerprint."""
    watched = ["core.time_civil_from_days", "http_profile.keyid"]
    before = {
        unit_id: measure(UNITS[unit_id])[
            "fingerprint"
        ]
        for unit_id in watched
    }
    for source in (
        "verification/lean/theorems/CivilFromDays.lean",
        "verification/lean/lakefile.toml",
    ):
        after = perturbed_fingerprints(source, watched)
        assert after["core.time_civil_from_days"] != before["core.time_civil_from_days"], source
        assert after["http_profile.keyid"] == before["http_profile.keyid"], source


def test_a_lean_file_outside_the_elaborated_closure_does_not_move_it():
    """Direction two, and the one that says the component is a SELECTION rather than a glob
    over `verification/lean/`.

    The cone is the one the lane elaborates: every lakefile root and what those import. A
    `.lean` file in a directory no `[[lean_lib]]` reads is elaborated by nothing, so a unit
    whose evidence came from `lake build` must not be dirtied by it."""
    from _manifest import REPO_ROOT as ROOT

    unrelated = ROOT / "verification/lean/models/NotInAnyLib.lean"
    assert not unrelated.exists(), "the fixture must not collide with a real file"
    before = measure(UNITS["core.time_civil_from_days"])["fingerprint"]
    try:
        unrelated.write_text("theorem unrelated : True := trivial\n", encoding="utf-8")
        after = measure(UNITS["core.time_civil_from_days"])["fingerprint"]
    finally:
        unrelated.unlink()
    assert after == before


def test_the_extraction_components_do_not_touch_the_specification_axis():
    """§14.3, asserted rather than argued. A theorem fingerprint reads `theorems.toml` and
    nothing else, so no instrument digest and no proof-source digest can reach an owner's
    specification approval — the two axes certify different things and are compared
    separately.

    Written as a measurement because the campaign has one instance (SF-009) where a proposed
    gate widening would have spent the owner's signature on eight theorems. An argument that
    a signature cannot be spent is worth less than an observation that it was not."""
    from _fingerprint import fingerprint_theorem
    from _theorems import load_theorems

    theorems = load_theorems(set(UNITS))
    rows = theorems.get("theorem", [])
    assert len(rows) > 100, len(rows)

    def claims():
        return {
            row["id"]: fingerprint_theorem(row, theorems)["fingerprint"] for row in rows
        }

    before = claims()
    # THM-0128 is the theorem this unit supports; naming it makes the control specific
    # rather than a statement about a dictionary.
    assert "THM-0128" in before
    for touched in (
        "tools/verification/_lean_axioms.py",
        "verification/lean/theorems/CivilFromDays.lean",
        "verification/lean/generated/McpReCore.lean",
    ):
        # MEASURED INSIDE the edit window. Measuring after the restore would assert that
        # `theorems.toml` equals itself.
        during = while_perturbed(touched, claims)
        assert during == before, touched

    # And the control, because a claim-fingerprint set that never moves would satisfy the
    # loop above for the wrong reason. The claim axis DOES move when its own input moves —
    # and note it is the parsed claim, not the file's bytes, so this is an edit to the
    # statement rather than a byte appended to the file.
    row = dict(next(r for r in rows if r["id"] == "THM-0128"))
    row["statement"] = row["statement"] + " (falsifier)"
    moved = fingerprint_theorem(row, theorems)["fingerprint"]
    assert moved != before["THM-0128"]


def test_the_generated_model_component_has_a_real_population():
    """P-c. `generated_inputs` is in the ADR's fingerprint equation and its invalidation
    rule is tested — `generated-model drift -> DIRTY_EVIDENCE` — but the component was
    computed from `unit["paths"] ∩ verification/lean/generated/**`, and NO unit lists a path
    there. Measured: 0 of 244 units had a non-empty one. A declared rule wired to an empty
    population is a rule that has never been able to fire.

    None of them should list one, either: a `.lean` path in a Rust unit's `paths` collapses
    `unit_ecosystem` to None and takes the test lane's target resolution with it. So the
    population is derived from the extraction declaration instead."""
    with_model = [
        unit_id for unit_id in UNITS if components(unit_id)["generated_inputs"]
    ]
    assert with_model == ["core.time_civil_from_days"], with_model
    assert set(components("core.time_civil_from_days")["generated_inputs"]) == {
        "verification/lean/generated/McpReCore.lean",
    }


def test_generated_model_drift_reaches_the_invalidation_verdict():
    """The whole chain, on the real manifest rather than on synthetic components:

        the model the unit consumes changes
            -> `generated_inputs` moves
            -> the unit fingerprint moves
            -> the standing attestation is no longer FRESH, and the reason NAMES the model.

    The attestation is built from the CURRENT components on purpose: a stale one would
    answer UNKNOWN for a different and less interesting reason — that it predates the
    encoding — and the property under test is the drift, not the upgrade."""
    from _graph import Attestation, derive_unit_state

    unit_id = "core.time_civil_from_days"
    before = measure(UNITS[unit_id])
    standing = Attestation(
        unit_id=unit_id,
        fingerprint=before["fingerprint"],
        components=before["components"],
        evidence={"lean": "pass", "generated-model": "pass", "test": "pass"},
    )
    assert derive_unit_state(unit_id, before, {unit_id: standing})[0] == "FRESH"

    after = while_perturbed(
        "verification/lean/generated/McpReCore.lean",
        lambda: measure(UNITS[unit_id]),
    )
    assert after["components"]["generated_inputs"] != before["components"]["generated_inputs"]
    assert after["fingerprint"] != before["fingerprint"]
    state, reason = derive_unit_state(unit_id, after, {unit_id: standing})
    assert state == "DIRTY_EVIDENCE", (state, reason)
    assert "generated_inputs" in reason, reason


def test_the_non_lean_population_is_untouched_by_the_model():
    """The control. A unit that asks no extraction lane for evidence must not be dirtied by
    the extracted model, or `generated_inputs` is measuring "somebody re-extracted" rather
    than "the input this unit's proof stands on changed"."""
    bystanders = ["http_profile.keyid", "core.time_rfc3339"]
    before = {
        unit_id: measure(UNITS[unit_id])[
            "fingerprint"
        ]
        for unit_id in bystanders
    }
    after = perturbed_fingerprints("verification/lean/generated/McpReCore.lean", bystanders)
    assert after == before
