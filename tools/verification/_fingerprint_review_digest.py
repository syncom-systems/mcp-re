# SPDX-License-Identifier: Apache-2.0
"""The semantic review digest — Ruling 35 §3.

Two questions about a theorem, answered by two digests:

  REVIEW_CURRENT        is what the owner READ still what the tree says? The claim, its
                        premises, and the semantic inputs of the units that support it:
                        the code and specifications the claim is about, the tests and
                        probes the review relied on, the proved and extracted symbols.
  EVIDENCE_ESTABLISHED  does a successful run vouch for the tree AS IT STANDS? The full
                        unit fingerprint — the semantic inputs plus every lane's identity,
                        the toolchain, the generated model, the policy revisions — matched
                        by an attestation (`_graph.derive_unit_state`).

A toolchain bump moves the second and not the first: the evidence must be re-run, and the
owner has nothing new to read. An edit to supporting source moves both. The partition
below is what decides which component is which, and it is CLOSED: a unit component that
appears in neither set is treated as semantic (`semantic_unit_components`), so a new
component can only cause extra review, never false currency, and the census in
`test_theorem_review` fails until someone places it.
"""

from __future__ import annotations

from _fingerprint_digest import canonical_digest

#: Unit components that determine WHAT A CLAIM IS ABOUT, and so participate in the review
#: digest. Source and specification inputs, the selection of tests and probes the review
#: relied on, the formal statement surface, the premises and the trust boundary they hang
#: on.
#:
#: `proof_dependencies` is here, not on the evidence side: it is the SOURCE of the crates a
#: formal unit's prover run quantifies over — the types and helpers a verified function's
#: contract is stated in terms of. That over-approximates (an unrelated edit to such a crate
#: asks for a re-read), which is the safe direction.
SEMANTIC_UNIT_COMPONENTS = frozenset(
    {
        "unit_id",
        "class",
        "source_inputs",
        "enabled_features",
        "proof_dependencies",
        "gate_controls",
        "exported_contracts",
        "consumed_contracts",
        "proved_symbols",
        "extracted_symbols",
        "lean_theorems",
        "lean_theorem_sources",
        "test_evidence_definition",
        "test_selection",
        "test_sources",
        "mutation_probes",
        "structural_probes",
        "measurements",
        "trusted_assumptions",
        "governing_boundaries",
    }
)

#: Unit components that decide whether a RUN still vouches for the semantic inputs, and
#: nothing about what is claimed: the encoding, the generated model (derived from source
#: that is itself semantic), the build configuration, each lane's own instrument, the
#: toolchain, and the policy revisions. A change here re-runs evidence; it does not ask the
#: owner to re-read.
EVIDENCE_UNIT_COMPONENTS = frozenset(
    {
        "encoding_version",
        "generated_inputs",
        "build_configuration",
        "test_lane_identity",
        "mutation_lane_identity",
        "structural_lane_identity",
        "measured_lane_identity",
        "verus_lane_identity",
        "lean_lane_identity",
        "generated_model_lane_identity",
        "toolchain_identity",
        "formal_model_revision",
        "threat_model_revision",
        "review_policy_revision",
    }
)

#: Versioned on its own: the review digest certifies something neither the unit nor the
#: theorem encoding does, and bumping one must not silently re-mean the others.
REVIEW_ENCODING_VERSION = 1


def semantic_unit_components(unit_fingerprint: dict) -> dict[str, str]:
    """One supporting unit's semantic inputs, each component mapped to its digest.

    Everything not on the evidence side, including a component nobody has placed yet —
    unplaced is semantic, so the failure mode of a forgotten classification is a re-read.
    Digested per component so a stale review can name WHAT moved.
    """
    return {
        name: canonical_digest(value)
        for name, value in sorted(unit_fingerprint["components"].items())
        if name not in EVIDENCE_UNIT_COMPONENTS
    }


def review_digest(
    theorem_fingerprint: dict,
    premises: dict[str, str] | None,
    unit_fingerprints: dict[str, dict],
    supported_by: list[str],
) -> dict | None:
    """The semantic evidence digest a specification review is current against.

        review_digest = H(claim, dependency claims, review requirement, premises,
                          semantic inputs of every supporting unit)

    None when it cannot be computed — a supporting unit with no fingerprint, or an unknown
    premise closure. None is not an empty digest: nothing can be current against it.
    """
    if premises is None:
        return None
    semantics: dict[str, dict[str, str]] = {}
    for target in supported_by:
        unit = str(target).removeprefix("unit://")
        fingerprint = unit_fingerprints.get(unit)
        if fingerprint is None:
            return None
        semantics[unit] = semantic_unit_components(fingerprint)
    theorem = theorem_fingerprint["components"]
    components = {
        "encoding_version": REVIEW_ENCODING_VERSION,
        "theorem_claim": theorem["theorem_claim"],
        "theorem_dependencies": theorem["theorem_dependencies"],
        "theorem_review_requirement": theorem["theorem_review_requirement"],
        "premises": dict(sorted(premises.items())),
        "supporting_semantics": semantics,
    }
    return {"fingerprint": canonical_digest(components), "components": components}


def theorem_review_digests(
    theorems: dict,
    theorem_fingerprints: dict[str, dict],
    premises: dict[str, dict[str, str] | None],
    unit_fingerprints: dict[str, dict],
) -> dict[str, dict | None]:
    """`review_digest` for every declared theorem."""
    return {
        row["id"]: review_digest(
            theorem_fingerprints[row["id"]],
            premises.get(row["id"]),
            unit_fingerprints,
            list(row.get("supported_by", [])),
        )
        for row in theorems.get("theorem", [])
    }
