# SPDX-License-Identifier: Apache-2.0
"""The theorem registry's declared system roots, and the direction of its edges."""

from __future__ import annotations

from _manifest import ManifestError
from _theorem_entries import deprecated_ids


def check_roots(doc: dict, ids: list[str]) -> None:
    """The declared system roots — ADR-MCPRE-059 §28.1, §28.8.

    `root_theorems` is the ONE authoritative statement of which claims are MCP-RE system
    security promises, and it is the source from which proof-tree completeness is derived.

    It is not inferred. "A theorem with no dependents" is a different property: an isolated
    local claim nobody has yet composed has no dependents and is emphatically not a system
    promise, so inferring roots that way would silently declare the registry complete the
    moment it was populated with leaves. Declaration is the only way a root becomes one.

    Fail-closed in every direction: an unknown id, a duplicate, or a deprecated claim named
    as a root would each leave the completeness derivation quantifying over something other
    than what the reviewer ratified.
    """
    where = "theorems.toml root_theorems"
    roots = doc["root_theorems"]
    if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
        raise ManifestError(f"{where}: must be a list of THM-NNNN strings")
    declared = set(ids)
    deprecated = deprecated_ids(doc)
    seen: set[str] = set()
    for root in roots:
        _check_root(where, root, seen, (declared, deprecated))
        seen.add(root)


def _check_root(where: str, root: str, seen: set[str], known: tuple[set[str], set[str]]) -> None:
    declared, deprecated = known
    if root in seen:
        raise ManifestError(
            f"{where}: duplicate root {root!r}. A root is declared once; a repeated "
            f"entry makes the completeness quantifier read over a multiset."
        )
    if root not in declared:
        raise ManifestError(
            f"{where}: {root!r} is not a declared theorem. A root naming nothing is a "
            f"system promise the tooling cannot resolve, so completeness would be "
            f"derived over a claim that does not exist."
        )
    if root in deprecated:
        raise ManifestError(
            f"{where}: {root!r} is deprecated. A withdrawn claim cannot carry a system "
            f"promise; declare its replacement as the root."
        )


def check_edge_directions(doc: dict, proof_edges: list[dict]) -> None:
    """A theorem's `depends_on` may not contradict a unit-level `PROOF_DEPENDENCY`.

    The two are not a duplicated authority, and they do not mean the same thing: the unit
    edge is about how evidence dirtiness propagates between units, the theorem edge about
    which claim is a logical premise of which (§28.4). A unit-level edge is therefore
    neither a reason to write a theorem edge nor a substitute for one. But where both
    exist over the same pair of owners they are two statements of one relation, and they
    may not disagree.

    `verification.toml` writes the edge producer-first: dirtiness flows along the arrow, so
    `from` is the LOWER unit and `to` consumes it. A theorem owned by `from` that depends on
    a theorem owned by `to` therefore inverts the declared direction, which is exactly the
    error this catches — a reviewer drafting from the prose reads "unbypassability
    establishes that the check runs; the contract establishes what it guarantees" and
    reasonably gets the arrow backwards.
    """
    if not proof_edges:
        return
    owner_of = {entry["id"]: entry["owner"] for entry in doc.get("theorem", [])}
    # `depends_on` runs consumer -> premise, and the unit edge runs premise -> consumer.
    # So the legal owner pair for a theorem edge is (edge.to, edge.from); the pair
    # (edge.from, edge.to) is a claim owned by the premise unit resting on a claim owned by
    # its consumer, which is the inversion.
    inverted = {(edge["from"], edge["to"]) for edge in proof_edges}
    for index, entry in enumerate(doc.get("theorem", [])):
        for target in entry.get("depends_on", []):
            pair = (owner_of[entry["id"]], owner_of.get(target))
            if pair in inverted:
                raise ManifestError(
                    f"theorems.toml [[theorem]] #{index} ({entry['id']}): depends_on "
                    f"{target!r} runs against the declared PROOF_DEPENDENCY. "
                    f"verification.toml declares {pair[0]} -> {pair[1]}, so a claim owned "
                    f"by {pair[0]} is the premise; {entry['id']} states the reverse."
                )
