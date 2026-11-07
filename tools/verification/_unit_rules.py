# SPDX-License-Identifier: Apache-2.0
"""The verification classes, and the rules that admit a unit's identity and proof selection."""

from __future__ import annotations

from _evidence_class import class_problems
from _evidence_class import severity_problem
from _lanes import claims
from _registries import ManifestError
import _tree


#: Verification classes, ADR-MCPRE-059 §9.
CLASSES = {"V0", "V1", "V2", "V3"}


#: The classes as an ordered scale, so "past the class this boundary permits" is a
#: comparison rather than a reading of the manifest by a human.
CLASS_ORDER = {"V0": 0, "V1": 1, "V2": 2, "V3": 3}


def validate_unit_identity(
    uwhere: str, unit: dict, seen_ids: set[str], tree_checks: bool
) -> None:
    """The record's own identity: declared class, unique id, and paths that resolve.

    Records `unit["id"]` in `seen_ids`, which is how a duplicate is caught across units.
    """
    _refuse_unadmitted_class(uwhere, unit)
    if unit["id"] in seen_ids:
        raise ManifestError(f"{uwhere}: duplicate unit id {unit['id']!r}")
    seen_ids.add(unit["id"])
    if tree_checks:
        _require_paths_resolve(uwhere, unit)


def _refuse_unadmitted_class(uwhere: str, unit: dict) -> None:
    """The declared class is a known one that the record's own evidence satisfies."""
    # ADR-MCPRE-068 §9.3, registry adequacy: declaring a class you do not satisfy is a
    # lie and is fatal here, at load, before anything reads the unit. Every rule
    # `class_problems` applies is computable from THIS record alone, which is what
    # keeps it loader-stage; N1's falsifier obligation needs `effective_severity` from
    # the assurance graph and activates in Phase 0E instead.
    for problem in class_problems(uwhere, unit):
        raise ManifestError(problem)
    problem = severity_problem(uwhere, unit)
    if problem is not None:
        raise ManifestError(problem)
    if unit["class"] not in CLASSES:
        raise ManifestError(
            f"{uwhere}: class {unit['class']!r} not one of {sorted(CLASSES)}"
        )


def _require_paths_resolve(uwhere: str, unit: dict) -> None:
    """Every declared path names at least one file in the current tree."""
    for declared in unit["paths"]:
        if not _tree.current().files(declared):
            raise ManifestError(
                f"{uwhere}: path {declared!r} matches nothing. A unit whose source "
                f"cannot be located has unknown provenance, which is dirty, not empty."
            )


def _require_extraction_selection(uwhere: str, unit: dict) -> None:
    """A V2/V3 unit names what the extracted-model lane measures, and says so in `evidence`.

    The extracted-model lane's two halves of the same argument, and they are separate
    keys because they name different things in different languages: which RUST items
    Charon starts from, and which LEAN theorems the prover is asked about. Deriving
    either from the other would be a guess about a name mangling that Aeneas owns.

    Kept apart from `proved_symbols` deliberately. That key is the Verus lane's, and a
    V3 unit claims BOTH lanes — one key read by two provers with two naming schemes is
    a key that means whichever the reader assumed.
    """
    for key, what in (
        ("extracted_symbols", "the Rust items the model is extracted from"),
        ("lean_theorems", "the Lean theorems the prover is asked about"),
    ):
        if not unit.get(key):
            raise ManifestError(
                f"{uwhere}: class {unit['class']} requires `{key}` — {what}. A "
                f"unit claiming extracted-model evidence with an empty selection "
                f"asks the lane to measure nothing, and nothing measured passes."
            )
    # AND IT MUST SAY SO IN ITS EVIDENCE. Two authorities read "what does this unit
    # require": `_evidence.required_lanes` derives it from the declared URIs, and the
    # aggregate's requirement set derives it from the class. They agree only while
    # every V2/V3 unit declares `lean://` — and nothing made it. A unit with the
    # selection keys above and no `lean://` entry would be ISSUED an attestation on
    # its test battery alone while claiming extracted-model evidence, because the
    # issuer would see no lean lane to check.
    if not claims(unit, "lean"):
        raise ManifestError(
            f"{uwhere}: class {unit['class']} declares an extraction selection but "
            f"no `lean://` evidence entry. The class says the Lean lane must "
            f"measure this unit and the evidence list is where a unit says which "
            f"lanes are asked about it, so the two must agree — otherwise the "
            f"issuer checks a lane the class requires and the manifest never named."
        )


def validate_proof_selection(uwhere: str, unit: dict) -> None:
    """What each proof class must name, and that no class names what no lane reads."""
    # A V1/V3 unit must name the symbols its proof is about. Without that the lane can
    # only ask "did this crate verify something", and deleting one of two
    # specifications leaves the other to answer yes — coverage silently halves while
    # the gate stays green. Naming them turns a deleted theorem into a lane failure.
    if unit["class"] in {"V1", "V3"} and not unit.get("proved_symbols"):
        raise ManifestError(
            f"{uwhere}: class {unit['class']} requires `proved_symbols`. A unit that "
            f"claims formal evidence must name the symbols proved, or nothing "
            f"distinguishes a deleted specification from a passing one."
        )
    if unit["class"] in {"V2", "V3"}:
        _require_extraction_selection(uwhere, unit)
    elif unit.get("extracted_symbols") or unit.get("lean_theorems"):
        raise ManifestError(
            f"{uwhere}: declares extraction selection but is class {unit['class']}, so "
            f"no lane reads it. A selection nothing consumes is a declaration that "
            f"reads as coverage and measures nothing."
        )
