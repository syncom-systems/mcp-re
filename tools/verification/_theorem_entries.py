# SPDX-License-Identifier: Apache-2.0
"""The shape of one `[[theorem]]` row: its keys, the facts it may not restate, its ids.

`_theorems` composes these checks with the edge, root and cycle rules.
"""

from __future__ import annotations

import re

from _manifest import ManifestError
from _record_rules import reject_unknown, require
from _evidence_class import severity_problem


#: `THM-NNNN`, matching the established `ASM-NNNN` convention.
_ID_RE = re.compile(r"^THM-\d{4}$")

TOP_KEYS = {"schema_version", "theorem", "root_theorems"}

_THEOREM_KEYS = {
    "id",
    "title",
    "statement",
    "security_consequence",
    "scope",
    "owner",
    "review_requirement",
    "supported_by",
    "depends_on",
    "replaced_by",
    # ADR-MCPRE-068 §10, S1. The CLOSED label beside the existing prose
    # `security_consequence`, which stays: the prose says what an attacker cannot do if the
    # claim holds, and the label says how much is lost if it does not. One is read by a
    # person and the other by the gate, and neither can be derived from the other.
    "direct_consequence_severity",
}
#: Everything but the deprecation link. A claim with no consequence or no scope is not a
#: reviewable proposition, so none of these is optional.
_REQUIRED_KEYS = _THEOREM_KEYS - {"replaced_by"}

#: Fields whose facts already have an owner. They are rejected by name because the generic
#: unknown-key message would send a reader looking for a typo when the real answer is
#: "that fact is declared elsewhere, and declaring it twice is how the two disagree".
_DUPLICATED_AUTHORITY = {
    "paths": "verification.toml [[unit]].paths",
    "features": "verification.toml [[unit]].features",
    "evidence": "verification.toml [[unit]].evidence",
    "proved_symbols": "verification.toml [[unit]].proved_symbols",
    "tested_symbols": "verification.toml [[unit]].tested_symbols",
    "exported_contracts": "verification.toml [[unit]].exported_contracts",
    "consumed_contracts": "verification.toml [[edge]].contract — derived from the incoming CONTRACT_CONSUMES edges, never authored",
    "assumptions": "assumptions.toml [[assumption]].scope — the one authoritative direction (§8)",
    "required_evidence": "verification.toml [[unit]].evidence, as target-qualified URIs",
    "review": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "review_status": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "reviewed": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "approved": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "status": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "root": "the top-level `root_theorems` set (§28.1) — root membership is declared once",
    "is_root": "the top-level `root_theorems` set (§28.1) — root membership is declared once",
    "root_claim": "the top-level `root_theorems` set (§28.1) — root membership is declared once",
    "consumed_by": "derived — a reverse edge is never stored (§8.2)",
    "dependents": "derived — a reverse edge is never stored (§8.2)",
    "guarantees": "derived from supported_by — a reverse edge is never stored (§8.2)",
    # ADR-MCPRE-068 N3 — both are DERIVED from the assurance graph and neither is ever
    # stored. A recorded copy is a value that can disagree with the graph it was computed
    # from, and the disagreement would be invisible: nothing re-derives a field that is
    # simply present.
    "severity": "the CLOSED label is `direct_consequence_severity` (§10, S1)",
    "consequence_severity": "the CLOSED label is `direct_consequence_severity` (§10, S1)",
    "effective_severity": "derived — max(direct, inherited), never stored (§9, N3)",
    "inherited_severity": "derived — from the roots and theorems above it, never stored (§9, N3)",
}

_TEXT_KEYS = (
    "title",
    "statement",
    "security_consequence",
    "scope",
    "owner",
    "review_requirement",
)


def _reject_duplicated_authority(where: str, entry: dict) -> None:
    for key, owner in _DUPLICATED_AUTHORITY.items():
        if key in entry:
            raise ManifestError(
                f"{where}: key {key!r} duplicates a fact owned by {owner}. One fact has "
                f"one authority; a theorem resolves downward through `unit://` rather "
                f"than restating what the unit already declares."
            )


def check_text(where: str, entry: dict) -> None:
    for key in _TEXT_KEYS:
        value = entry[key]
        if not isinstance(value, str) or not value.strip():
            raise ManifestError(
                f"{where}: {key} must be a non-empty string. An empty claim reads as a "
                f"registered theorem while stating nothing."
            )


def check_list(where: str, entry: dict, key: str) -> list[str]:
    value = entry[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ManifestError(f"{where}: {key} must be a list of strings")
    return value


def _check_entry(where: str, entry: dict) -> str:
    """The shape of one `[[theorem]]`, and its id."""
    _reject_duplicated_authority(where, entry)
    reject_unknown(where, entry, _THEOREM_KEYS)
    require(where, entry, _REQUIRED_KEYS)
    problem = severity_problem(where, entry)
    if problem is not None:
        raise ManifestError(problem)
    theorem_id = entry["id"]
    if not isinstance(theorem_id, str) or not _ID_RE.match(theorem_id):
        raise ManifestError(
            f"{where}: id {theorem_id!r} is not of the form THM-NNNN. An identifier "
            f"the tooling cannot resolve names no claim while reading as one."
        )
    return theorem_id


def check_ids(doc: dict) -> list[str]:
    """Every declared id, in declaration order, after format and uniqueness checks."""
    ids: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(doc.get("theorem", [])):
        where = f"theorems.toml [[theorem]] #{index}"
        theorem_id = _check_entry(where, entry)
        if theorem_id in seen:
            raise ManifestError(
                f"{where}: duplicate theorem id {theorem_id!r}. Ids are never reused — a "
                f"reused id makes two different security claims indistinguishable in the "
                f"review history."
            )
        seen.add(theorem_id)
        ids.append(theorem_id)
    return ids


def deprecated_ids(doc: dict) -> set[str]:
    return {entry["id"] for entry in doc.get("theorem", []) if entry.get("replaced_by")}
