# SPDX-License-Identifier: Apache-2.0
"""The security theorem registry — ADR-MCPRE-059 §6.3, Phase T1.

Loads and validates `verification/policy/theorems.toml`, strictly in the same sense as
`_manifest.py`: an unknown key is a validation FAILURE, not a field that is ignored.

The registry holds the human claim and two edges — `supported_by` (`unit://`) and
`depends_on` (`THM-NNNN`). Everything below the claim has an existing authority, so a key
that would restate a `[[unit]]` fact is rejected by name rather than merely as unknown.

`depends_on` means LOGICAL IMPLICATION and nothing else (§28.4): B is a premise required to
establish A. It is not "A's function calls B's function", not "A's owner imports B's
module", and not a build dependency between their units. Where the implication and the call
coincide, the implication is the reason and the call is the coincidence.

It also holds the one top-level declaration this layer owns: `root_theorems`, the claims
that are MCP-RE system security promises (§28.1). Roots are declared, never inferred, and
they are the source from which proof-tree completeness is derived (§28.8) — a property
distinct from evidence freshness, and derived in `_review`.

Two things this module refuses to do, both deliberate:

  * It stores no review or approval field. An approval is evidence about a fingerprint
    (§14.7), and a stored status string cannot say which proposition was approved.
  * It derives no reverse edge (§8.2). `structurally_supported_theorems` reads the declared
    direction only, and its name says exactly how far that reaches: a resolving support
    closure is not assurance, and nothing here may be read as "established" or "proved".

The limit of the ID-permanence rule, stated rather than implied: this loader sees the tree
as it stands, so it can enforce uniqueness and format but cannot see that an ID was
deleted and later reused. Deprecation keeps the record present, which is what makes the
rule checkable at review time; deletion is what a reviewer must catch.

Stdlib only, like the rest of `tools/verification/`.
"""

from __future__ import annotations

import _registries
from _manifest import SCHEMA_VERSION, ManifestError
from _theorem_closure import root_theorems, structurally_supported_theorems, unsupported_theorems
from _record_rules import reject_unknown, require
from _theorem_rules import check_edge_directions, check_roots
from _theorem_entries import TOP_KEYS, check_ids, check_list, check_text, deprecated_ids


def _check_owner(where: str, entry: dict, unit_ids: set[str]) -> None:
    if entry["owner"] not in unit_ids:
        raise ManifestError(
            f"{where}: owner {entry['owner']!r} is not a [[unit]] declared in "
            f"verification.toml. `owner` names the review unit that is the semantic "
            f"authority for the claim, so an owner nothing resolves leaves the claim "
            f"unowned while reading as governed."
        )


def _is_declared_unit(target: str, unit_ids: set[str]) -> bool:
    return target.startswith("unit://") and target[7:] in unit_ids


def _check_support(where: str, entry: dict, unit_ids: set[str]) -> None:
    for target in check_list(where, entry, "supported_by"):
        # Fail closed. A dangling support edge would otherwise contribute nothing to
        # the closure, and a closure with nothing in it is satisfied vacuously — the
        # theorem would read as supported by evidence that does not exist.
        if not _is_declared_unit(target, unit_ids):
            raise ManifestError(
                f"{where}: supported_by {target!r} does not resolve to a [[unit]] "
                f"declared in verification.toml. An unresolvable support edge derives "
                f"an empty closure, which is satisfied vacuously — so it fails here "
                f"rather than passing there."
            )


def _depends_problem(entry: dict, target: str, declared: set[str], deprecated: set[str]) -> str | None:
    """Why `target` is not a legal premise of `entry`, or None."""
    if target == entry["id"]:
        return "depends_on names itself"
    if target not in declared:
        return f"depends_on {target!r} is not a declared theorem"
    if target in deprecated and entry["id"] not in deprecated:
        return (f"depends_on {target!r}, which is deprecated. A live claim "
                f"may not rest on a withdrawn one; depend on its replacement.")
    return None


def _check_depends(where: str, entry: dict, declared: set[str], deprecated: set[str]) -> None:
    for target in check_list(where, entry, "depends_on"):
        problem = _depends_problem(entry, target, declared, deprecated)
        if problem is not None:
            raise ManifestError(f"{where}: {problem}")


def _check_replacement(where: str, entry: dict, declared: set[str], deprecated: set[str]) -> None:
    replacement = entry.get("replaced_by")
    if replacement is None:
        return
    if replacement == entry["id"] or replacement not in declared:
        raise ManifestError(
            f"{where}: replaced_by {replacement!r} is not another declared theorem. A "
            f"deprecated theorem stays resolvable and links what replaced it."
        )
    if replacement in deprecated:
        raise ManifestError(
            f"{where}: replaced_by {replacement!r}, which is itself deprecated. The "
            f"link must reach a live claim, or the reader follows it to nothing."
        )


def _check_edges(doc: dict, ids: list[str], unit_ids: set[str]) -> None:
    declared = set(ids)
    deprecated = deprecated_ids(doc)
    for index, entry in enumerate(doc.get("theorem", [])):
        where = f"theorems.toml [[theorem]] #{index} ({entry['id']})"
        check_text(where, entry)
        _check_owner(where, entry, unit_ids)
        _check_support(where, entry, unit_ids)
        _check_depends(where, entry, declared, deprecated)
        _check_replacement(where, entry, declared, deprecated)


def _find_cycle(edges: dict[str, list[str]]) -> list[str] | None:
    """The first `depends_on` cycle, as the nodes along it, or None."""
    state: dict[str, int] = {}

    def walk(node: str, stack: list[str]) -> list[str] | None:
        if state.get(node) == 2:
            return None
        if state.get(node) == 1:
            return stack[stack.index(node):] + [node]
        state[node] = 1
        found = next((c for c in (walk(nxt, stack + [node]) for nxt in edges.get(node, []))
                      if c is not None), None)
        state[node] = 2
        return found

    return next((c for c in (walk(node, []) for node in edges) if c is not None), None)


def _check_acyclic(doc: dict) -> None:
    """Reject a cycle in `depends_on`.

    The gate covers registry-declared edges only. It does not claim to see a cycle formed
    below the registry, through units or contracts — those have their own owners.
    """
    cycle = _find_cycle({
        entry["id"]: list(entry.get("depends_on", []))
        for entry in doc.get("theorem", [])
    })
    if cycle is not None:
        raise ManifestError(
            f"theorems.toml: cycle in depends_on: {' -> '.join(cycle)}. A claim that "
            f"transitively depends on itself is established by nothing."
        )


def validate_theorems(
    doc: dict, unit_ids: set[str], proof_edges: list[dict] | None = None
) -> dict:
    """Validate a parsed theorem registry against the declared review units."""
    where = "theorems.toml"
    reject_unknown(where, doc, TOP_KEYS)
    require(where, doc, {"schema_version", "root_theorems"})
    if doc["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling implements "
            f"{SCHEMA_VERSION}. A schema change alters what a claim means, so it must be "
            f"handled, not tolerated."
        )
    ids = check_ids(doc)
    check_roots(doc, ids)
    _check_edges(doc, ids, unit_ids)
    check_edge_directions(doc, proof_edges or [])
    _check_acyclic(doc)
    return doc


def load_theorems(unit_ids: set[str], proof_edges: list[dict] | None = None) -> dict:
    """Load and validate `verification/policy/theorems.toml`.

    `proof_edges` are `verification.toml`'s `PROOF_DEPENDENCY` entries. Passing them turns
    on the direction check; omitting them skips it, so a caller that has not loaded the
    unit catalogue's edges cannot silently claim the stronger validation.
    """
    doc = _registries.document("theorems", required=True)
    return validate_theorems(doc, unit_ids, proof_edges)
