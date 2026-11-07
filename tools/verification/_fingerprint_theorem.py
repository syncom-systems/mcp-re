# SPDX-License-Identifier: Apache-2.0
"""The theorem axis of the fingerprint — ADR-MCPRE-059 §14.1, §14.3, §14.7.

A theorem fingerprint is SEPARATE from the fingerprint of the units that support it, and
the separation is the whole mechanism §14.3 asks for:

  * A theorem's supporting unit fingerprints are NOT components here. This digest is the
    claim surface the correction chain and the claim-surface gate are about. What the
    owner read the claim against — premises and the supporting units' SEMANTIC inputs —
    is the separate `review_digest` (`_fingerprint_review_digest`), which leaves toolchain,
    lane and policy identity to the evidence axis.
  * Conversely a unit fingerprint carries no theorem component, so restating a claim
    leaves the prover green. That is exactly the situation the mutation test pins: the
    theorem moves from F1 to F2 while the review record still names F1, so specification
    review derives DIRTY with no legislative rule and no stored status string.

Whether the two axes are BOTH fresh is a conjunction, computed in `_review`, and it is
the only place the word "established" is allowed to appear.
"""

from __future__ import annotations

from _fingerprint_digest import assumption_digest
from _fingerprint_digest import canonical_digest
from _premise import is_model_registration

#: Versioned independently of the unit encoding. Bumping one must not invalidate the other:
#: they certify different things and are compared separately.
THEOREM_ENCODING_VERSION = 1


def _claim_digest(entry: dict) -> str:
    """The canonical digest of the human claim — §14.1's `theorem_claim`.

    Exactly `statement + security_consequence + scope`, as the ADR names them. `title` is
    excluded because it is a label for humans, not part of the proposition; renaming a
    theorem must not invalidate a review of what it says.
    """
    return canonical_digest(
        {
            "statement": entry["statement"],
            "security_consequence": entry["security_consequence"],
            "scope": entry["scope"],
        }
    )


def _dependency_closure(theorem_id: str, by_id: dict[str, dict]) -> dict[str, str]:
    """The transitive `depends_on` closure, each premise mapped to ITS claim digest.

    Ids alone would let a premise be weakened — its statement narrowed, its scope widened —
    without any dependent theorem moving, which is the composition-shaped version of the
    same false green `trusted_assumptions` closes one layer down. The closure is transitive
    because a claim rests on everything underneath it, not only its direct premises.

    The registry's loader rejects cycles, so the walk terminates; `seen` is kept anyway, as
    a fingerprint that could be made to hang by a malformed input is a denial of the gate.
    """
    out: dict[str, str] = {}
    stack = list(by_id[theorem_id].get("depends_on", []))
    seen: set[str] = {theorem_id}
    while stack:
        dep = stack.pop()
        if dep in seen or dep not in by_id:
            continue
        seen.add(dep)
        out[dep] = _claim_digest(by_id[dep])
        stack.extend(by_id[dep].get("depends_on", []))
    return out


def fingerprint_theorem(entry: dict, theorems: dict) -> dict:
    """Deterministic fingerprint over one theorem's specification.

    `review_requirement` participates: an approval given under "Owner security-specification
    review" is not an approval under a weaker requirement, so relaxing who must review is a
    change to what the approval meant. Leaving it out would make the one edit that lowers
    the review bar the one edit that dirties nothing.
    """
    by_id = {row["id"]: row for row in theorems.get("theorem", [])}
    components = {
        "encoding_version": THEOREM_ENCODING_VERSION,
        "theorem_id": entry["id"],
        "theorem_claim": _claim_digest(entry),
        "theorem_dependencies": _dependency_closure(entry["id"], by_id),
        "theorem_review_requirement": entry["review_requirement"],
    }
    return {
        "theorem_id": entry["id"],
        "fingerprint": canonical_digest(components),
        "components": components,
    }


def _registered_models(assumptions: dict) -> set[str]:
    return {
        entry["id"]
        for entry in assumptions.get("assumption", [])
        if is_model_registration(entry)
    }


def _boundary_attachments(entry: dict, registrations: set[str]) -> list[str]:
    """The boundaries an assumption attaches to by naming ONLY boundaries.

    None for a model registration, whose trust is attributed to the premise that interprets
    it, and for an assumption that names units, which attaches to exactly those.
    """
    scope = [str(target) for target in entry.get("scope", [])]
    if entry["id"] in registrations or any(t.startswith("unit://") for t in scope):
        return []
    return [t.removeprefix("boundary://") for t in scope if t.startswith("boundary://")]


def _boundary_premises(
    assumptions: dict, registrations: set[str]
) -> dict[str, dict[str, str]]:
    """Each boundary's attached assumptions: boundary id -> assumption id -> digest."""
    by_boundary: dict[str, dict[str, str]] = {}
    for entry in assumptions.get("assumption", []):
        for boundary in _boundary_attachments(entry, registrations):
            by_boundary.setdefault(boundary, {})[entry["id"]] = assumption_digest(entry)
    return by_boundary


def _absorb_premises(
    closure: dict[str, str],
    components: dict,
    registrations: set[str],
    by_boundary: dict[str, dict[str, str]],
) -> None:
    """Add one supporting unit's premises, direct and through the boundaries it crosses."""
    closure.update(
        (asm_id, digest)
        for asm_id, digest in components["trusted_assumptions"].items()
        if asm_id not in registrations
    )
    for boundary in components["governing_boundaries"]:
        closure.update(by_boundary.get(boundary, {}))


def _premise_closure(
    row: dict,
    unit_fingerprints: dict[str, dict],
    registrations: set[str],
    by_boundary: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    """One theorem's closure, or None when a supporting unit has no fingerprint."""
    closure: dict[str, str] = {}
    for target in row.get("supported_by", []):
        fingerprint = unit_fingerprints.get(str(target).removeprefix("unit://"))
        if fingerprint is None:
            return None
        _absorb_premises(closure, fingerprint["components"], registrations, by_boundary)
    return dict(sorted(closure.items()))


def theorem_premises(
    theorems: dict, unit_fingerprints: dict[str, dict], assumptions: dict
) -> dict[str, dict[str, str] | None]:
    """Each theorem's premise closure: assumption id -> current `assumption_digest`.

    A theorem rests on the premises its supporting units are scoped to. Two attachment
    rules, by what the assumption's `scope` names (r12 defect D):

      * an assumption that names UNITS attaches to exactly those units. Its `boundary://`
        entries say which boundary it discharges for them (`boundary_class_violations`),
        not that every other unit crossing the boundary rests on it too;
      * an assumption that names ONLY boundaries attaches to every unit whose files cross
        one of them (`governing_boundaries`), because nothing narrower was stated.

    Spreading a unit-scoped premise to every crosser was over-inclusive — a theorem about a
    window comparison carried the PKCS#11 and Redis premises of every other unit in the same
    crate — and narrowing a scope changed no closure. The converse gap, a unit that CALLS
    into a boundary from outside its files, is closed by DATA: the premise's scope names the
    consuming unit.

    A `model-registration` (r12 Ruling 39 §4) is dropped: its trust is attributed to the
    premise that interprets it, which `registration_problems` requires to reach every unit
    the registration does. A theorem with a supporting unit that has no fingerprint maps to
    None: its closure is unknown, not empty.
    """
    registrations = _registered_models(assumptions)
    by_boundary = _boundary_premises(assumptions, registrations)
    return {
        row["id"]: _premise_closure(row, unit_fingerprints, registrations, by_boundary)
        for row in theorems.get("theorem", [])
    }
