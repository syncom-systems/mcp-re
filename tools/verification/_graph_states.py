# SPDX-License-Identifier: Apache-2.0
"""The vocabulary of unit freshness: the state precedence, which recorded component produces
which state, the components that cannot differ, and the ones deliberately left unclassified."""

from __future__ import annotations

#: Precedence when several inputs moved at once. The reported state is the FIRST match, so
#: a reviewer is told the most fundamental reason rather than an incidental one: a unit
#: whose own source and whose upstream contract both changed is `DIRTY_SELF`, because its
#: own code has to be read either way.
STATE_PRECEDENCE = (
    "BLOCKED",
    "UNKNOWN",
    "DIRTY_POLICY",
    "DIRTY_TOOLCHAIN",
    "DIRTY_ASSUMPTION",
    "DIRTY_SELF",
    "DIRTY_CONTRACT",
    "DIRTY_EVIDENCE",
    "DIRTY_DEPENDENCY",
    "FRESH",
)

#: Which recorded component, when it differs, produces which state.
#:
#: This table was written for Phase 4's twelve components and did not grow with the
#: encoding. Eighteen of the thirty components `fingerprint_unit` produces were in neither
#: it nor any other list, so each of them reached `derive_unit_state`'s last resort —
#: `UNKNOWN`, "this engine cannot classify it". Fail-closed, and there is no path from it to
#: FRESH, so nothing was unsound. What was lost is the thing §5 asks these states to be:
#: `DIRTY_SELF` versus `DIRTY_CONTRACT` versus `DIRTY_EVIDENCE` are answers to WHICH input
#: moved, and a reviewer needs that answer to know what work the change created. "Something
#: this engine cannot classify" is not that answer.
#:
#: Every entry added below is DETERMINED by the encoding's own statement about what the
#: component refines — not chosen for a tidier state. `_fingerprint.py` says of each one
#: which earlier component it makes effective, and the refinement inherits that component's
#: classification. Where the encoding does NOT determine it, the component is in
#: `UNRESOLVED_COMPONENT` and keeps deriving UNKNOWN.
COMPONENT_STATE = {
    # --- Phase 4's original twelve ---------------------------------------------------
    "source_inputs": "DIRTY_SELF",
    "exported_contracts": "DIRTY_CONTRACT",
    # The consumer's half of the same relation, and a different state on purpose.
    # `DIRTY_CONTRACT` is the PRODUCER whose published interface moved; a change to WHICH
    # producer contract this unit consumes is neither that nor consumer implementation
    # churn — it is a change to the dependency closure the unit's evidence rests on. Applied
    # only now, because until the value was derived from the incoming CONTRACT_CONSUMES
    # edges it was an independently authored field, and classifying one of three
    # representations that had never had to agree would have fixed the reading of a
    # disagreement instead of removing it.
    "consumed_contracts": "DIRTY_DEPENDENCY",
    "test_evidence_definition": "DIRTY_EVIDENCE",
    "trusted_assumptions": "DIRTY_ASSUMPTION",
    "toolchain_identity": "DIRTY_TOOLCHAIN",
    "review_policy_revision": "DIRTY_POLICY",
    "formal_model_revision": "DIRTY_POLICY",
    "threat_model_revision": "DIRTY_POLICY",
    "enabled_features": "DIRTY_SELF",
    "build_configuration": "DIRTY_SELF",
    "generated_inputs": "DIRTY_EVIDENCE",
    "proof_dependencies": "DIRTY_EVIDENCE",
    # --- v4: the EFFECTIVE test evidence, not merely its label ------------------------
    # "Encoding v4 measures the EFFECTIVE TEST EVIDENCE" — these three answer "what did the
    # test lane actually measure" for the claim `test_evidence_definition` states. A
    # refinement of a component classified DIRTY_EVIDENCE is DIRTY_EVIDENCE: the battery
    # behind the claim moved, which is the same fact at a finer grain.
    "test_selection": "DIRTY_EVIDENCE",
    "test_sources": "DIRTY_EVIDENCE",
    "test_lane_identity": "DIRTY_EVIDENCE",
    # --- v5: "extends the same rule to the MUTATION evidence" -------------------------
    "mutation_probes": "DIRTY_EVIDENCE",
    "mutation_lane_identity": "DIRTY_EVIDENCE",
    # --- ADR-MCPRE-068 Phase 0D: "the same closure the mutation components give" -------
    "structural_probes": "DIRTY_EVIDENCE",
    "structural_lane_identity": "DIRTY_EVIDENCE",
    "measurements": "DIRTY_EVIDENCE",
    "measured_lane_identity": "DIRTY_EVIDENCE",
    # --- v8: the extracted-model SELECTION, "for the reason v3 added the test selection"
    "extracted_symbols": "DIRTY_EVIDENCE",
    "lean_theorems": "DIRTY_EVIDENCE",
    # --- the PROOF lane's own identity ------------------------------------------------
    # The seventh lane, and the same sentence the other six carry: the code that decides
    # what "a machine-checked proof passed" MEANS is part of that result's identity. A
    # refinement of the formal evidence, so it takes the classification of what it refines.
    "verus_lane_identity": "DIRTY_EVIDENCE",
    # --- the extraction lanes' own identity, and the theorem TEXT ---------------------
    # The same three sentences the four host lane identities already carry, for the two
    # lanes that had none: the code deciding what a `lean://` or generated-model result
    # MEANS is part of that result's identity, and the theorem the prover resolves is the
    # claim rather than its label. All three refine the extraction evidence, so they take
    # the classification of what they refine.
    "lean_lane_identity": "DIRTY_EVIDENCE",
    "generated_model_lane_identity": "DIRTY_EVIDENCE",
    "lean_theorem_sources": "DIRTY_EVIDENCE",
    # The theorems a formal unit claims, by prover-reported name. Same shape as
    # `test_evidence_definition`: it states WHAT is claimed, and deleting one is a reduction
    # in evidence that the source digest would not report.
    "proved_symbols": "DIRTY_EVIDENCE",
    # --- the boundary cap ------------------------------------------------------------
    # `max_class_without_assumption` is what keeps a proof's meaning honest across a
    # declared trust boundary — a premise about what may be trusted beyond it, which is what
    # `trusted_assumptions` already carries. Relaxing the cap relaxes an assumption.
    "governing_boundaries": "DIRTY_ASSUMPTION",
}

#: Components that CANNOT differ between an attestation and the current derivation, because
#: the comparison is keyed on them or short-circuits before reading them. Listed rather than
#: omitted so that the census below can range over every produced component.
STRUCTURAL_COMPONENT = {
    # Skipped explicitly in `derive_unit_state`: a moved encoding is UNKNOWN by fingerprint
    # comparison, which is a stronger statement than any per-component one.
    "encoding_version",
    # Attestations are looked up BY unit id, so a differing one means a corrupt record. It
    # keeps deriving UNKNOWN, which is the right answer to a record that is not about this
    # unit.
    "unit_id",
}

#: Produced, and deliberately NOT classified. Each derives UNKNOWN — fail-closed, and more
#: conservative than any `DIRTY_*` — because the encoding does not determine which state it
#: is, and a classification is not free: a sealed `CONTRACT_CONSUMES` edge stops propagation
#: for `DIRTY_SELF` and `DIRTY_EVIDENCE` and for nothing else, so classifying a component
#: can REDUCE what an invalidation reaches. Zero sealed edges are declared today, which
#: makes the choice unobservable now and load-bearing the moment one is.
#:
#: These three are the owner's, and the value here is the question, not a placeholder.
UNRESOLVED_COMPONENT = {
    "class": (
        "a unit's class decides which lanes are REQUIRED of it, so a reclassification "
        "changes what evidence must exist rather than what any evidence measured. That is "
        "arguably DIRTY_POLICY and arguably DIRTY_EVIDENCE, and the encoding says neither."
    ),
    "gate_controls": (
        "ADR-MCPRE-068 Phase 1 describes these as 'the production carrier of the "
        "proposition it defends' and says softening one is 'a reduction in evidence "
        "exactly as deleting a runtime check is'. The first phrase points at DIRTY_SELF "
        "and the second at DIRTY_EVIDENCE, in one sentence."
    ),
}
