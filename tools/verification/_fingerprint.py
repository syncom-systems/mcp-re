# SPDX-License-Identifier: Apache-2.0
"""Deterministic ReviewFingerprint over a review unit — ADR-MCPRE-059 §2.

    ReviewFingerprint(U) = H(
        source_inputs, generated_inputs, build_configuration, enabled_features,
        exported_contracts, consumed_contracts, proof_dependencies,
        test_evidence_definition, test_selection, test_sources, test_lane_identity,
        mutation_probes, mutation_lane_identity, trusted_assumptions, toolchain_identity,
        formal_model_revision, threat_model_revision, review_policy_revision
    )

Freshness is DERIVED by comparing this against the inputs recorded in a successful
attestation. There is no mutable `clean = true` anywhere, because a mutable marker is easy
to stale and easy to manipulate.

Two properties the encoding must have, and does:

  * Deterministic. Sorted keys, explicit separators, UTF-8, no timestamps, no run ids.
    Provenance may be attached to an attestation; it may not enter the semantic fingerprint.
  * Versioned. `encoding_version` participates in the hash, so changing how inputs are
    encoded changes every fingerprint — which is correct, since the meaning changed.

Every component is MEASURED. There is no sentinel value standing in for an input nobody
computes: a constant compares equal on every run, so a component recorded as one is inert
and the freshness derivation silently establishes nothing over it. A component with no
matching inputs is an empty mapping — measured, and empty — which is a different claim from
"not accounted for" and the only one this encoding can make.

Encoding v4 measures the EFFECTIVE TEST EVIDENCE, not merely its label. Until v3 the only
test component was `test_evidence_definition` — the sorted `test://` URIs — so a battery
could fall from 67 declared controls to 5, or move to a different project, with the URI and
therefore the fingerprint unchanged. Four components now answer "what did the test lane
actually measure":

  * `test_evidence_definition`  the `test://` URIs, as before — WHAT is claimed
  * `test_selection`            the resolved project, the exact sorted symbols, and each
                                Rust test target's row in the build graph — its crate root
                                and the crate features it compiles under — WHICH tests were
                                selected, in which configuration
  * `test_sources`              the bytes of the integration-test targets those selectors
                                run. A selector on a target built from a crate is NOT here:
                                it executes code inside the unit's declared `paths`, which
                                `source_inputs` already digests, and the manifest loader
                                REFUSES one whose module is not declared, so that is a
                                checked fact rather than a hope.
  * `test_lane_identity`        the selector mechanism itself — `verify-tests` and the
                                manifest logic it reads. What a selector names is decided by
                                that code; if the measuring instrument changes, what the
                                measurement MEANS changed.

Encoding v5 extends the same rule to the MUTATION evidence. A `mutation://` URI puts the
probe suite inside the attestation closure — `attest` refuses a unit with no mutation PASS
at its exact fingerprint — but a closure over a suite that can silently SHRINK proves as
little as the v3 test component did. So:

  * `mutation_probes`        each in-scope probe's id mapped to a digest of its whole
                             registry entry. Deleting a probe, widening its `expect_red`,
                             or softening its weakening all move the fingerprint, which
                             invalidates the standing mutation PASS.
  * `mutation_lane_identity` `verify-mutations`, for the reason `test_lane_identity`
                             carries `verify-tests`: this lane decides what "the control
                             went red" MEANS, and it has already been wrong about it once —
                             the first version counted a control that never executed as
                             red.

An integration-test target is digested as a whole file (plus any module directory beside
it), not as the subset of it the selectors name. That over-approximates — an unrelated test
in the same file invalidates the unit — and over-approximation is the safe direction: it
causes extra review, never false freshness. It narrows once there is an executable
dependency boundary to narrow to.

Encoding v8 adds the EXTRACTED-MODEL selection, for the reason v3 added the test selection
and v5 the mutation probes: a `lean://` claim rests on a selection that could otherwise
shrink in silence.

  * `extracted_symbols`      the Rust items Charon starts from. They decide what the model
                             CONTAINS, so narrowing them narrows every theorem proved
                             against it while the theorem text stands still.
  * `lean_theorems`          the theorems the prover is asked about, by the name it
                             resolves. Deleting one is a reduction in evidence exactly as
                             deleting a `proved_symbol` is, and the source digest would not
                             say so — the theorem lives in `verification/lean/`, not in the
                             unit's declared `paths`.

The EXTRACTION lanes were the exception to all of it, and the exception was silent. Four
lanes carried their runner; `lean` and `generated-model` carried nothing, so `verify-lean`,
`check-generated` and the model predicate could be narrowed with no `lean://` unit deriving
DIRTY. The selection (v8) was measured and the instrument was not. Three components close
it, all CONDITIONAL — added only where the unit declares `lean://`, on the `gate_controls`
precedent, because one unit declares it and an always-present key would move the other 243
fingerprints to record an absence:

  * `lean_lane_identity`             what decides that the theorems STAND: the runner, the
                                     axiom accounting, the prover query, the model
                                     predicate, the container identity and the manifest.
                                     The JUDGEMENT cone, not the import closure — the test
                                     for membership is whether changing the file can alter
                                     whether the lane reports valid evidence, which theorems
                                     were activated, or whether a run that elaborated
                                     nothing is accepted.
  * `generated_model_lane_identity`  what decides that the committed model IS the model this
                                     tree extracts, including `regenerate-lean`: the pinned
                                     Charon and Aeneas are in `toolchain_identity`, the
                                     INVOCATION is not.
  * `lean_theorem_sources`           the bytes the declared `lean_theorems` are stated in.
                                     The names alone let a claim be emptied — a theorem
                                     rewritten to `: True := trivial` resolves under its own
                                     name with an axiom closure inside the kernel baseline —
                                     which is the v3 test defect at the CLAIM rather than at
                                     the instrument. Derived from the lakefile's libraries
                                     by `_lean_sources`, so the elaborated cone and the
                                     measured cone are one fact.

`generated_inputs` was in the equation from the start and was computed from the unit's
declared paths ∩ `verification/lean/generated/`. No unit lists a path there — 0 of 244 — and
none should, because a `.lean` path in a Rust unit collapses its ecosystem. So the rule
`generated-model drift -> DIRTY_EVIDENCE` was wired to an empty population. It is now
derived from the same extraction declaration.

`_fingerprint.py` is deliberately NOT in `test_lane_identity`. Its identity is carried by
`ENCODING_VERSION`, which is what a change of MEANING here must move; hashing the file
would additionally invalidate every unit for a comment.

The measured cone is the cone the LANE measures, not the paths the unit lists. The Verus
lane verifies the whole crate against its first-party dependencies, so a formal unit's
`source_inputs` covers every `.rs` file in the crate its paths name and its
`proof_dependencies` covers the first-party crates that crate depends on. A
fingerprint narrower than the verified cone lets source the proof stands on change while
the graph still answers FRESH.

Importable as a module — `_graph` and `review-frontier` both need `fingerprint_unit`, and
the `fingerprint` command is a thin CLI over it. It lives here rather than in the
extensionless script because an extensionless file cannot be imported.
"""

from __future__ import annotations

import _rust_targets
import _tree
from _boundary_crossings import FORMAL_CLASSES
from _ecosystems import RUST
from _ecosystems import unit_ecosystem
from _fingerprint_boundaries import declared_boundaries
from _fingerprint_boundaries import governing_boundaries
from _fingerprint_digest import assumption_digest
from _fingerprint_digest import canonical_digest
from _fingerprint_digest import collect_reads
from _fingerprint_digest import digest_paths
from _fingerprint_digest import record
from _fingerprint_evidence import RUST_TARGETS_TABLE
from _fingerprint_evidence import consumed_contracts
from _fingerprint_evidence import mutation_probes
from _fingerprint_evidence import registry_entries
from _fingerprint_evidence import test_selection
from _fingerprint_evidence import test_source_patterns
from _fingerprint_evidence import test_sources
from _fingerprint_evidence import trusted_assumptions
from _fingerprint_lanes import GENERATED_MODEL_LANE_INPUTS
from _fingerprint_lanes import LEAN_LANE_INPUTS
from _fingerprint_lanes import MEASURED_LANE_INPUTS
from _fingerprint_lanes import MUTATION_LANE_INPUTS
from _fingerprint_lanes import STRUCTURAL_LANE_INPUTS
from _fingerprint_lanes import TEST_LANE_INPUTS
from _fingerprint_lanes import VERUS_LANE_INPUTS
from _fingerprint_lanes import generated_model_lane_identity
from _fingerprint_lanes import lean_lane_identity
from _fingerprint_lanes import measured_lane_identity
from _fingerprint_lanes import mutation_lane_identity
from _fingerprint_lanes import structural_lane_identity
from _fingerprint_lanes import test_lane_identity
from _fingerprint_lanes import verus_lane_identity
from _fingerprint_review_digest import EVIDENCE_UNIT_COMPONENTS
from _fingerprint_review_digest import REVIEW_ENCODING_VERSION
from _fingerprint_review_digest import SEMANTIC_UNIT_COMPONENTS
from _fingerprint_review_digest import review_digest
from _fingerprint_review_digest import semantic_unit_components
from _fingerprint_review_digest import theorem_review_digests
from _fingerprint_sources import GENERATED_ROOT
from _fingerprint_sources import build_configuration
from _fingerprint_sources import crate_sources
from _fingerprint_sources import formal_sources
from _fingerprint_sources import generated_inputs
from _fingerprint_sources import toolchain_identity
from _fingerprint_sources import unit_crates
from _fingerprint_theorem import THEOREM_ENCODING_VERSION
from _fingerprint_theorem import fingerprint_theorem
from _fingerprint_theorem import theorem_premises
from _lanes import claims
from _lean_sources import LAKEFILE
from _lean_sources import theorem_source_paths
from _manifest import REPO_ROOT
from _manifest import TOOLCHAINS_LOCK_TOML
from _manifest import VERIFICATION_TOML
from _assumptions import ASSUMPTIONS_TOML
from _trust_boundaries import TRUST_BOUNDARIES_TOML

__all__ = [
    "ENCODING_VERSION",
    "EVIDENCE_UNIT_COMPONENTS",
    "GENERATED_MODEL_LANE_INPUTS",
    "GENERATED_ROOT",
    "LEAN_LANE_INPUTS",
    "MEASURED_LANE_INPUTS",
    "MUTATION_LANE_INPUTS",
    "POLICY_DOCUMENTS",
    "REVIEW_ENCODING_VERSION",
    "RUST_TARGETS_TABLE",
    "SEMANTIC_UNIT_COMPONENTS",
    "STRUCTURAL_LANE_INPUTS",
    "TEST_LANE_INPUTS",
    "THEOREM_ENCODING_VERSION",
    "VERUS_LANE_INPUTS",
    "WORKSPACE_BUILD_INPUTS",
    "assumption_digest",
    "canonical_digest",
    "fingerprint_read_set",
    "fingerprint_theorem",
    "fingerprint_unit",
    "review_digest",
    "semantic_unit_components",
    "test_source_patterns",
    "theorem_premises",
    "theorem_review_digests",
    "toolchain_identity",
]

# Every attestation carrying an earlier version is UNKNOWN from the moment this moves, which
# is the intended cost: an attestation computed over a narrower set of inputs cannot answer
# whether one of the inputs it never saw has since changed.
ENCODING_VERSION = 10

#: Build inputs that decide what the verified crate IS, for every Rust unit. A dependency
#: swap, a lockfile bump or a toolchain pin change alters what a theorem is about without
#: touching a line of the source the unit declares. Bazel's, because Bazel builds it.
WORKSPACE_BUILD_INPUTS = RUST.workspace_inputs

#: The registries a caller parses and hands `fingerprint_unit` as documents. Their bytes
#: reach the digest through the parsed values — the policy revision, a unit's own entry, the
#: in-scope assumptions, the crossed boundaries — so each is in every unit's read set.
POLICY_DOCUMENTS = tuple(
    path.relative_to(REPO_ROOT).as_posix()
    for path in (VERIFICATION_TOML, TOOLCHAINS_LOCK_TOML, ASSUMPTIONS_TOML, TRUST_BOUNDARIES_TOML)
)

def _tracked_files() -> frozenset[str]:
    """Every path git tracks in the tree being measured, as repo-relative POSIX strings.

    A fingerprint describes the COMMITTED tree, and every explicitly declared input already
    is one. The glob-driven inputs are not, and an untracked file among them makes the same
    commit fingerprint two ways depending on whose machine looked — a measurement of
    something nobody reviewed rather than a stricter measurement.

    The instance this rule was written for has since been repaired rather than tolerated:
    `sdk/python/uv.lock` was `.gitignore`d as a maturin by-product, so the Python dependency
    resolution sat in `project_inputs` and contributed NOTHING to any fingerprint. It is
    tracked now, and `scripts/prepare_python_matrix.sh` builds every runtime environment
    from it — so the resolution the batteries ran under is the one the fingerprint carries
    (issue #746). The filter stays, because it is what keeps that repair honest: a lock that
    goes back to being ignored silently leaves the closure again, and the filter is what
    makes that a measured absence rather than a machine-dependent digest.
    """
    return _tree.current().tracked()


def _proof_closure(crates: list[str]) -> tuple[dict[str, str], list[str]]:
    """The first-party crates a prover run compiles alongside `crates`, and their source.

    Returned with the closure itself, because the build configuration of those crates is
    digested too: the source of a crate and the manifest that decides what it IS are the
    same input to the question.
    """
    record(RUST_TARGETS_TABLE)
    closure: set[str] = set()
    for crate in crates:
        closure |= _rust_targets.dependency_closure(crate)
    formal_closure = sorted(closure - set(crates))
    return crate_sources(formal_closure), formal_closure


def _source_components(unit: dict) -> dict:
    """The source, generated-model and build-configuration components.

    A formal unit's evidence comes from a whole-crate prover run, so the crate is the
    measured object. Digesting only the declared paths would leave every other file the
    theorem reads — the types it quantifies over, the helpers it calls — free to change
    under an attestation that still derives FRESH.
    """
    crates = unit_crates(unit)
    source_inputs = digest_paths(unit["paths"])
    proof_dependencies: dict[str, str] = {}
    formal_closure: list[str] = []
    if unit["class"] in FORMAL_CLASSES:
        source_inputs |= formal_sources(unit)
        proof_dependencies, formal_closure = _proof_closure(crates)
    return {
        "source_inputs": source_inputs,
        "generated_inputs": generated_inputs(unit),
        "build_configuration": build_configuration(unit, formal_closure),
        "proof_dependencies": proof_dependencies,
    }


def _declaration_components(unit: dict) -> dict:
    """What the unit declares it claims, as sorted lists."""
    return {
        "enabled_features": sorted(unit.get("features", [])),
        # The theorems the unit claims, by prover-reported name. In the fingerprint
        # because deleting one is a reduction in evidence: the source digest would move
        # too, but the contract digest would not, and this is the component that says the
        # CLAIM changed rather than its implementation.
        "proved_symbols": sorted(unit.get("proved_symbols", [])),
        # The extracted-model selection, both halves. `extracted_symbols` decides what the
        # model contains and `lean_theorems` what is claimed about it; neither is reachable
        # from `source_inputs`, because the theorem text lives in `verification/lean/` and
        # the selection lives in this manifest.
        "extracted_symbols": sorted(unit.get("extracted_symbols", [])),
        "lean_theorems": sorted(unit.get("lean_theorems", [])),
        "exported_contracts": sorted(unit.get("exported_contracts", [])),
        "test_evidence_definition": sorted(unit.get("evidence", [])),
    }


def _evidence_components(unit: dict, doc: dict) -> dict:
    """The components that measure what the unit's evidence actually ran."""
    return {
        "consumed_contracts": consumed_contracts(unit, doc),
        "test_selection": test_selection(unit),
        "test_sources": test_sources(unit),
        "test_lane_identity": test_lane_identity(unit),
        "mutation_probes": (
            mutation_probes(unit["id"]) if claims(unit, "mutation") else {}
        ),
        "mutation_lane_identity": mutation_lane_identity(unit),
        # ADR-MCPRE-068 Phase 0D. The same closure the mutation components give the negative
        # battery, for the two classes whose falsifiers are a refused COMPILATION and a
        # moving APPARATUS. Empty for every unit that does not declare the scheme, which is
        # why they could not land at 0B: a component that is `{}` everywhere would have
        # spent a whole re-attestation on nothing.
        "structural_probes": (
            registry_entries("structural-probes", "probe", unit["id"])
            if claims(unit, "structural")
            else {}
        ),
        "structural_lane_identity": structural_lane_identity(unit),
        "measurements": (
            registry_entries("measurements", "measurement", unit["id"])
            if claims(unit, "measured")
            else {}
        ),
        "measured_lane_identity": measured_lane_identity(unit),
    }


def _governance_components(unit: dict, assumptions: dict, boundaries: dict | None) -> dict:
    """The premises the unit trusts and the trust boundaries whose cap binds it."""
    return {
        "trusted_assumptions": trusted_assumptions(unit["id"], assumptions),
        # The boundaries whose cap binds this unit's class. See `governing_boundaries`:
        # the cap was a gate that participated in no fingerprint, so relaxing it left every
        # claim above it reading as fresh.
        "governing_boundaries": governing_boundaries(
            unit, declared_boundaries() if boundaries is None else boundaries
        ),
    }


def _revision_components(unit: dict, doc: dict, toolchains: dict) -> dict:
    """The pinned toolchains and the model, threat and review-policy revisions."""
    ecosystem = unit_ecosystem(unit)
    return {
        "toolchain_identity": toolchain_identity(
            toolchains, ecosystem.name if ecosystem is not None else None
        ),
        "formal_model_revision": doc.get("formal_model_revision"),
        "threat_model_revision": doc.get("threat_model_revision"),
        "review_policy_revision": doc["policy_revision"],
    }


def _conditional_components(unit: dict) -> dict:
    """The components added ONLY WHERE THE UNIT DECLARES the scheme they measure.

    A key present-but-empty on every other unit would move every fingerprint and invalidate
    every standing attestation, to record the absence of a thing none of them has.
    """
    components: dict = {}
    # ADR-MCPRE-068 Phase 1. The rules of a gate control are the production carrier of the
    # proposition it defends, so softening one is a reduction in evidence exactly as
    # deleting a runtime check is. The scripts cannot go in `paths` — a `.py` path in a
    # Rust unit collapses `unit_ecosystem` to None and takes the test lane's target
    # resolution with it — so they are digested as their own component instead.
    if unit.get("gate_controls"):
        components["gate_controls"] = digest_paths(sorted(unit["gate_controls"]))
    # The seventh formal lane, and the last one whose instrument was outside the identity.
    # 238 of 244 units claim no `verus://`, and an always-present key would move all of
    # them to record the absence of a thing they never had. The population it does reach is
    # the repository's entire machine-checked surface — the same six units that declare
    # `proved_symbols`, export a `contract://`, and carry class V1.
    if claims(unit, "verus"):
        components["verus_lane_identity"] = verus_lane_identity(unit)
    # The extraction lanes' identity, for `lean://`: one unit declares the scheme today.
    #
    # Two lane components rather than one shared list. `lean` and `generated-model` answer
    # different propositions — *do the theorems stand* and *is the committed model the one
    # this tree extracts* — and a unit could in principle come to claim one without the
    # other. They overlap in `_lean_model.py` and `_extraction_identity.py`, and the overlap
    # is the honest statement that those two decide something for both.
    if claims(unit, "lean"):
        components["lean_lane_identity"] = lean_lane_identity()
        components["generated_model_lane_identity"] = generated_model_lane_identity()
        # The BYTES the declared `lean_theorems` are stated in. `lean_theorems` is a list of
        # names, and a name survives its own statement being emptied: rewrite the theorem to
        # `: True := trivial` and it still resolves, still reports an axiom closure inside
        # the kernel baseline, and still leaves the standing PASS deriving FRESH.
        #
        # Derived from the lakefile rather than listed: the build definition is what decides
        # which modules elaborate, and a second list would drift from it. The lakefile joins
        # the digest because it decides what the set CONTAINS.
        components["lean_theorem_sources"] = digest_paths([LAKEFILE, *theorem_source_paths()])
    return components


def fingerprint_unit(
    unit: dict,
    doc: dict,
    toolchains: dict,
    assumptions: dict,
    boundaries: dict | None = None,
) -> dict:
    components = {
        "encoding_version": ENCODING_VERSION,
        "unit_id": unit["id"],
        "class": unit["class"],
        **_source_components(unit),
        **_declaration_components(unit),
        **_evidence_components(unit, doc),
        **_governance_components(unit, assumptions, boundaries),
        **_revision_components(unit, doc, toolchains),
        **_conditional_components(unit),
    }
    return {
        "unit_id": unit["id"],
        "fingerprint": canonical_digest(components),
        "components": components,
    }


def fingerprint_read_set(
    unit: dict,
    doc: dict,
    toolchains: dict,
    assumptions: dict,
    boundaries: dict | None = None,
) -> frozenset[str]:
    """Every repo path whose bytes can move this unit's fingerprint.

    Computed by fingerprinting the unit and recording what was read, so the answer cannot
    drift from the encoding: a component added to `fingerprint_unit` reads through
    `digest_paths` or a registry, and both record. The trigger gate checks the
    verification workflow re-runs on every path in it.

    Tracked files, plus wildcard-free inputs nothing occupies yet — creating one of those
    moves the digest, so a filter naming it is live.
    """
    reads = collect_reads(
        lambda: fingerprint_unit(unit, doc, toolchains, assumptions, boundaries)
    )
    return frozenset(reads | set(POLICY_DOCUMENTS))
