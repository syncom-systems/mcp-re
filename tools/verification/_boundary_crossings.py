# SPDX-License-Identifier: Apache-2.0
"""Which trust boundaries a unit's proof crosses, and the class cap that follows."""

from __future__ import annotations

from _ecosystems import unit_projects
from _manifest import CLASS_ORDER
from _registries import REPO_ROOT
from _seams import files_with_seams
import _rust_targets
import _tree


def expand_paths(patterns) -> set[str]:
    """The repo-relative files a `paths` list names in the current tree, globs expanded."""
    return _tree.expand(patterns)


#: The classes whose evidence comes from a whole-crate run rather than from a battery over
#: declared symbols. Defined here rather than in the fingerprint because the fingerprint and
#: the boundary rule must agree about what a unit's evidence covers.
#:
#: V2 is here for the reason V1 is, one tool along. The Verus lane checks the whole crate;
#: Charon compiles the whole crate and follows the named item into whatever it calls, so
#: the extracted model's cone is decided inside the tool and is not reported by it. Both are wider than the declared paths, and a
#: fingerprint narrower than the measured cone lets source a proof stands on change while
#: the graph still answers FRESH.
FORMAL_CLASSES = {"V1", "V2", "V3"}


#: The classes whose proof lane can CONSUME a seam `_seams` recognises. Those mechanisms are
#: Verus', written in Rust and read by the Verus lane; a Lean theorem over an extracted model
#: cannot consume one, because the spec items carrying them are behind the `verify` feature
#: and are never compiled into the extraction. See `boundary_class_violations`, which is the
#: one place this distinction decides anything.
RUST_SEAM_CONSUMERS = {"V1", "V3"}


def evidence_cone(unit: dict) -> set[str]:
    """INVALIDATION REACHABILITY: every source file whose change must stale this evidence.

    For a formal unit that is the whole crate plus the first-party crates it depends on,
    because the whole-crate run — the prover, the extractor — compiles all of them. For a V0
    unit it is the declared paths, which is what its battery measures.

    This is the FIRST of the two graphs R9-C022 turned out to be about, and it is
    deliberately generous: a file in here changing invalidates the evidence even if it
    contributes no premise to any proof. Over-invalidation is safe. It is NOT a statement
    that the proof depends on anything in here semantically — see `semantic_boundary_crossings`.
    """
    declared = expand_paths(unit["paths"])
    if unit["class"] not in FORMAL_CLASSES:
        return declared
    projects: set[str] = set()
    for project in unit_projects(unit):
        projects |= _rust_targets.dependency_closure(project)
    cone = set(declared)
    for project in sorted(projects):
        cone |= expand_paths([f"{project}/src/**/*.rs"])
    return cone


def semantic_boundary_crossings(unit: dict, boundaries: dict) -> dict[str, list[str]]:
    """TRUSTED-PREMISE REACHABILITY: boundaries whose files this proof actually TRUSTS.

    The second graph, and the one the class cap belongs to. A boundary is crossed
    SEMANTICALLY when a file it declares carries a TRUSTED SEAM — an `uninterp`, an
    `external_body`, an `assume_specification` — that lies inside this unit's evidence cone.
    A seam is the only place a proof stops proving and starts trusting, so it is the only
    place an unproved proposition can enter one.

    R9-C022, and the owner ruling of 2026-09-03 that closed it. The rule compared a
    boundary's files against the unit's DECLARED paths, which was too narrow; widening it to
    the evidence cone made all six V1 units "cross" `boundary.crypto_primitives`, which is
    too wide in a way that is worse. Neither `mcp-re-core/src/crypto.rs` nor `hash.rs`
    contains a single seam: the six proofs are COMPILED alongside the primitives and consume
    no proposition from them. Requiring six crypto assumptions there would have invented
    premises to satisfy a source-level overlap — assumptions nobody could justify, in a
    registry whose value is that every entry names something real.

        proof consumes an unproved proposition beyond the boundary
            -> explicit registered assumption required

        proof merely shares the compilation/invalidation cone
            -> fingerprint is conservatively invalidated, and NO premise is invented

    Returns `{boundary id: [seam file, ...]}` so a refusal can name the seam it found rather
    than the overlap it computed.

    WHAT THIS DOES NOT CATCH, stated because a control's blind spot is part of what it
    establishes. A seam is attributed to a boundary by LOCATION: it must sit in a file the
    boundary declares. A premise that MODELS a boundary's semantics from somewhere else is
    invisible here — `verus_std_specs.rs` holds `uninterp spec fn labeled_digest`, which is
    the digest as an uninterpreted function, while `boundary.crypto_primitives` declares
    only `crypto.rs` and `hash.rs`. ASM-0037 bridges exactly that gap by naming
    `boundary://boundary.crypto_primitives` in its own scope, which is the declared half of
    the relation and is why `scope` accepts a boundary at all.

    So the mechanism is a FLOOR with a declared complement, not a decision procedure:
    `check-assumptions` already refuses any unregistered seam, so no seam goes unaccounted
    for; what is not forced is that a seam's assumption also names the boundary it crosses.
    Closing that would mean requiring a boundary's `paths` to cover the files where its
    premises are modelled, which is a change to what a boundary declaration MEANS and is not
    made here.
    """
    cone = evidence_cone(unit)
    crossings: dict[str, list[str]] = {}
    for boundary in boundaries.get("boundary", []):
        seams = sorted(files_with_seams(REPO_ROOT, expand_paths(boundary["paths"]) & cone))
        if seams:
            crossings[boundary["id"]] = seams
    return crossings


def boundary_class_violations(
    verification: dict, boundaries: dict, assumptions: dict
) -> list[str]:
    """Units promoted past the class a boundary they cross permits.

    `max_class_without_assumption` is the rule that keeps a proof's meaning honest across a
    trust boundary: a theorem about code on this side says nothing about the other side, so
    claiming V1/V2/V3 over an FFI, crypto, KMS or clock boundary is an over-read unless a
    registered assumption states what is being trusted there.

    A crossing is COVERED when some assumption's `scope` names both the unit and the
    boundary. Naming only the unit is not enough — that is the assumption's ordinary scope,
    and it says nothing about which boundary it discharges.

    THE CAP IS ASKED OF THE LANE THAT CAN CONSUME THE SEAM. `_seams` recognises VERUS
    mechanisms written in Rust — `uninterp`, `assume_specification`, `external_body` — and
    those are propositions the Verus lane trusts. A V2 unit's proof is a Lean theorem over a
    model Charon extracted from compiled Rust: the spec items carrying those mechanisms are
    behind the `verify` feature, are not compiled into the extraction, and do not appear in
    the model at all. Reading them as premises of a Lean theorem would be R9-C022 one lane
    over — a premise invented out of a source-level overlap, in a registry whose whole value
    is that every entry names something real.

    That is a decision about a case that has never arisen rather than a relaxation of one
    that has: the cap can only fire above `max_class_without_assumption`, every declared cap
    is V0, and until now every unit above V0 was a Verus unit. What it must not become is an
    unguarded lane, and it is not one. The extracted model's premises are its AXIOM CLOSURE,
    `verify-lean` discovers that closure with `#print axioms` rather than by location, and
    every axiom outside the declared kernel baseline must be an `ASM-NNNN` scoped to the
    unit or the lane refuses. An assumption there names its boundary in its own `scope`, the
    way ASM-0037 names `boundary://boundary.crypto_primitives` — which is the declared half
    of the relation this function's own docstring calls a floor with a declared complement.
    """
    covered = _covered_crossings(assumptions)
    caps = {
        boundary["id"]: boundary["max_class_without_assumption"]
        for boundary in boundaries.get("boundary", [])
        if boundary.get("max_class_without_assumption") is not None
    }
    violations: list[str] = []
    # Once per unit: the crossings are a property of the unit's proof, not of the boundary
    # being asked about, and computing them inside the boundary loop rescanned every seam
    # file once per boundary.
    for unit in verification.get("unit", []):
        if unit["class"] in RUST_SEAM_CONSUMERS:
            violations.extend(_uncovered_crossings(unit, boundaries, caps, covered))
    return sorted(violations)


def _covered_crossings(assumptions: dict) -> set[tuple[str, str]]:
    """The `(unit id, boundary id)` pairs some assumption's `scope` names together."""
    covered: set[tuple[str, str]] = set()
    for entry in assumptions.get("assumption", []):
        scope = [str(target) for target in entry.get("scope", [])]
        units = [t.removeprefix("unit://") for t in scope if t.startswith("unit://")]
        crossed = [
            t.removeprefix("boundary://") for t in scope if t.startswith("boundary://")
        ]
        for unit_id in units:
            for boundary_id in crossed:
                covered.add((unit_id, boundary_id))
    return covered


def _uncovered_crossings(
    unit: dict, boundaries: dict, caps: dict[str, str], covered: set[tuple[str, str]]
) -> list[str]:
    """One refusal per boundary this unit's proof trusts past that boundary's class cap."""
    violations: list[str] = []
    for boundary_id, seams in semantic_boundary_crossings(unit, boundaries).items():
        cap = caps.get(boundary_id)
        if cap is None or CLASS_ORDER[unit["class"]] <= CLASS_ORDER[cap]:
            continue
        if (unit["id"], boundary_id) in covered:
            continue
        violations.append(
            f"unit {unit['id']} is class {unit['class']} and its proof TRUSTS a seam "
            f"beyond {boundary_id} ({', '.join(seams)}), which permits at most {cap} "
            f"without a registered assumption covering the crossing. The seam is an "
            f"unproved proposition the proof consumes, not a file it is compiled "
            f"beside. Register an assumption in assumptions.toml with "
            f"`boundary://{boundary_id}` in its scope, or lower the unit's class."
        )
    return violations
