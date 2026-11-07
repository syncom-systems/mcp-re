# SPDX-License-Identifier: Apache-2.0
"""The boundary a unit's evidence cone crosses: the class cap, the assumption that discharges it, and the two graphs (invalidation cone and trusted frontier) the owner ruling separated."""

from __future__ import annotations

from _assumptions import load_assumptions
from _boundary_crossings import boundary_class_violations
from _trust_boundaries import load_trust_boundaries
from _measured_inputs_support import (
    DOC,
    UNITS,
    components,
    measure,
    scoped,
)


# --- the boundary a unit's paths cross -----------------------------------------


BOUNDARIES = {
    "boundary": [
        {
            "id": "boundary.clock",
            "description": "d",
            "kind": "environment",
            "paths": ["mcp-re-core/src/time/mod.rs"],
            "beyond": "b",
            "max_class_without_assumption": "V0",
        }
    ]
}

CROSSING_UNIT = {
    "unit": [
        {"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time/mod.rs"]},
    ]
}


def test_a_unit_promoted_past_a_crossed_boundarys_cap_is_a_violation():
    violations = boundary_class_violations(CROSSING_UNIT, BOUNDARIES, scoped())
    assert len(violations) == 1
    assert "boundary.clock" in violations[0]


def test_scoping_an_assumption_to_the_unit_alone_does_not_cover_the_crossing():
    """The ordinary unit scope says nothing about which boundary the assumption discharges,
    so accepting it would make the cap unenforceable the moment a unit had any assumption."""
    violations = boundary_class_violations(
        CROSSING_UNIT, BOUNDARIES, scoped("unit://u")
    )
    assert len(violations) == 1


def test_an_assumption_naming_both_the_unit_and_the_boundary_covers_it():
    violations = boundary_class_violations(
        CROSSING_UNIT, BOUNDARIES, scoped("unit://u", "boundary://boundary.clock")
    )
    assert violations == []


def test_a_unit_at_or_below_the_cap_is_not_a_violation():
    below = {"unit": [{"id": "u", "class": "V0", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
    assert boundary_class_violations(below, BOUNDARIES, scoped()) == []


def test_a_v0_unit_whose_paths_do_not_reach_the_seam_is_untouched():
    """A V0 unit's cone IS its declared paths, because its evidence is a battery over
    declared symbols. So declaring a file elsewhere in the crate reaches no seam."""
    elsewhere = {
        "unit": [{"id": "u", "class": "V0", "paths": ["mcp-re-core/src/hash.rs"]}]
    }
    assert boundary_class_violations(elsewhere, BOUNDARIES, scoped()) == []


def test_a_formal_units_cone_reaches_a_seam_its_declared_paths_do_not():
    """This test previously asserted the OPPOSITE, and the assertion was wrong.

    A V1 unit declaring `hash.rs` is verified by `//mcp-re-core:mcp_re_core_verus`, so the
    prover checks the whole crate — including the `external_body` in `time/mod.rs`. The
    proof really does consume that unproved proposition, and the old rule could not see it
    because it compared the boundary against DECLARED PATHS. Declared paths are what a unit
    is ABOUT; they are not what its proof reaches.

    This is the half of R9-C022 that was a genuine under-detection, and it survives the
    owner ruling of 2026-09-03 — the ruling narrowed what counts as a crossing (a seam, not
    a file), not how far a formal proof reaches."""
    elsewhere = {
        "unit": [{"id": "u", "class": "V1", "paths": ["mcp-re-core/src/hash.rs"]}]
    }
    violations = boundary_class_violations(elsewhere, BOUNDARIES, scoped())
    assert len(violations) == 1, violations
    assert "mcp-re-core/src/time/mod.rs" in violations[0]


# ---------------------------------------------------------------------------
# R9-C022 — the two graphs, and the four controls the owner ruling required
# ---------------------------------------------------------------------------
#
#   EVIDENCE INVALIDATION CONE     whole formal crate + path-dependency inputs
#                                  -> decides when evidence goes stale
#   TRUSTED SEMANTIC FRONTIER      unproved propositions the proof CONSUMES
#                                  -> decides assumptions and boundary crossings
#
# The first may be larger than the second, and conflating them is what made the corrected
# cone rule demand six crypto assumptions nobody could justify. A theorem may live in
# cryptographically rich code while its proved proposition consumes no cryptographic
# premise — which is exactly the state of this tree.


def _seam_boundary(tmp_rel):
    """A synthetic boundary over one real file that DOES carry a seam."""
    return {
        "boundary": [
            {
                "id": "boundary.synthetic",
                "description": "d",
                "kind": "cryptographic",
                "paths": [tmp_rel],
                "beyond": "b",
                "max_class_without_assumption": "V0",
            }
        ]
    }


def test_control_1_compilation_proximity_alone_invents_no_assumption():
    """CONTROL 1. A V1 unit whose FORMAL SOURCE cone contains a crypto-boundary file, but
    whose proof consumes no crypto proposition, must NOT acquire a crypto assumption.

    This is the live case, not a synthetic one: all six V1 units are verified over crates
    whose cone contains `mcp-re-core/src/crypto.rs` and `hash.rs`, and NEITHER file carries
    a single trusted seam. The proofs are compiled beside the primitives and consume nothing
    from them."""
    from _boundary_crossings import evidence_cone, semantic_boundary_crossings

    boundaries = load_trust_boundaries()
    crypto_files = {"mcp-re-core/src/crypto.rs", "mcp-re-core/src/hash.rs"}
    formal = [u for u in DOC["unit"] if u["class"] in {"V1", "V3"}]
    assert formal
    reached = 0
    for unit in formal:
        if crypto_files & evidence_cone(unit):
            reached += 1
            assert "boundary.crypto_primitives" not in semantic_boundary_crossings(
                unit, boundaries
            ), unit["id"]
    assert reached, "no V1 unit's cone contains the crypto files; the control measures nothing"
    assert boundary_class_violations(DOC, boundaries, load_assumptions()) == []


def test_control_2_a_consumed_premise_without_its_assumption_fails_validation():
    """CONTROL 2. A V1/V3 proof that ACTUALLY consumes an unproved boundary proposition must
    fail manifest validation when the required explicit assumption is absent.

    `mcp-re-core/src/time/mod.rs` carries a real `external_body`, so a boundary declaring it
    is a boundary this unit's proof genuinely trusts."""
    doc = {"unit": [{"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
    violations = boundary_class_violations(
        doc, _seam_boundary("mcp-re-core/src/time/mod.rs"), scoped()
    )
    assert len(violations) == 1, violations
    assert "TRUSTS a seam" in violations[0]


def test_control_3_a_cone_file_with_no_premise_still_stales_the_evidence():
    """CONTROL 3. Changing a file in the formal invalidation cone must still stale the
    evidence even if that file contributes no semantic premise.

    The two graphs are independent in the direction that matters: narrowing what counts as
    a CROSSING must not narrow what counts as an INPUT. `crypto.rs` contributes no premise
    to any proof — control 1 — and must still be a fingerprint component of every V1 unit
    whose crate contains it."""
    unit = UNITS["core.time_rfc3339"]
    components = measure(unit)["components"]
    measured = set(components["source_inputs"]) | set(
        components.get("proof_dependencies", {})
    )
    assert "mcp-re-core/src/crypto.rs" in measured
    assert "mcp-re-core/src/hash.rs" in measured
    assert "mcp-re-core/src/crypto.rs" not in unit["paths"]


def test_control_4_removing_a_registered_premise_turns_the_gate_red():
    """CONTROL 4. Removing a real registered boundary premise from a proof that consumes it
    must turn the relevant gate red."""
    doc = {"unit": [{"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
    boundaries = _seam_boundary("mcp-re-core/src/time/mod.rs")
    covered = scoped("unit://u", "boundary://boundary.synthetic")
    assert boundary_class_violations(doc, boundaries, covered) == []
    assert len(boundary_class_violations(doc, boundaries, scoped("unit://u"))) == 1


def test_control_5_a_lean_unit_does_not_consume_a_rust_seam():
    """CONTROL 5. The cap is asked of the lane that can consume the seam.

    `_seams` recognises VERUS mechanisms written in Rust. A V2 unit's proof is a Lean
    theorem over a model Charon extracted from compiled Rust, and the spec items carrying
    those mechanisms are behind the `verify` feature — never compiled into the extraction,
    never present in the model. Reading them as premises of a Lean theorem is control 1's
    error one lane over: a premise invented out of a source-level overlap.

    The distinction is the LANE, not the file: the same file under the Verus lane still
    fails, which is control 2. What replaces the cap for the Lean lane is the axiom closure
    — `#print axioms`, every name outside the declared kernel baseline registered and scoped
    — and `test_lean_axioms.py` is where that is measured.
    """
    boundaries = _seam_boundary("mcp-re-core/src/time/mod.rs")
    lean = {"unit": [{"id": "u", "class": "V2", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
    verus = {"unit": [{"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
    assert boundary_class_violations(lean, boundaries, scoped()) == []
    assert len(boundary_class_violations(verus, boundaries, scoped())) == 1


def test_control_6_a_lean_units_invalidation_cone_is_still_the_whole_crate():
    """CONTROL 6. Narrowing what counts as a CROSSING must not narrow what counts as an
    INPUT — control 3's property, restated for the lane control 5 exempts.

    Charon's `--start-from <item>` compiles the whole crate and follows the named item
    into whatever it calls, so which files the extracted model depends on is decided inside
    the tool and is not reported by it. The cone stays the crate, and a file that
    contributes no premise still stales the evidence.
    """
    from _boundary_crossings import evidence_cone

    unit = {
        "id": "u",
        "class": "V2",
        "paths": ["mcp-re-core/src/time/format.rs"],
        "extracted_symbols": ["mcp_re_core::time::format::civil_from_days"],
        "lean_theorems": ["X.y"],
    }
    cone = evidence_cone(unit)
    assert "mcp-re-core/src/crypto.rs" in cone
    assert "mcp-re-core/src/time/mod.rs" in cone
    assert "mcp-re-core/src/time/format.rs" in cone


def test_the_frontier_is_seams_and_the_cone_is_files():
    """The distinction stated as an assertion rather than a comment: for a formal unit the
    cone is strictly larger than the frontier's file set, and the frontier is a subset of
    files that actually carry a seam."""
    from _boundary_crossings import evidence_cone, semantic_boundary_crossings
    from _seams import files_with_seams
    from _manifest import REPO_ROOT as ROOT

    boundaries = load_trust_boundaries()
    unit = UNITS["core.time_rfc3339"]
    cone = evidence_cone(unit)
    frontier = {f for files in semantic_boundary_crossings(unit, boundaries).values() for f in files}
    assert frontier <= cone
    assert frontier == files_with_seams(ROOT, frontier)
    assert len(cone) > len(frontier)
