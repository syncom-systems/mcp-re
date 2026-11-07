# SPDX-License-Identifier: Apache-2.0
"""Root completeness — ADR-MCPRE-059 §28.8.

Freshness asks whether the registry still describes the tree; completeness asks whether the
claims ratified as system promises are closed. Neither implies the other, which is why
this lives apart from `theorem_assurance`: the two can never be reported as one number.
"""

from __future__ import annotations

from _review_model import COMPLETE, INCOMPLETE, PREMISE_UNREVIEWED, REVIEWED, UNDECLARED


def closure_satisfied(roots: dict) -> bool:
    """Whether closure mode may pass — ADR-MCPRE-059 §28.8.

    Only `COMPLETE`. `UNDECLARED` fails here as surely as `INCOMPLETE`: a release that
    states no system promise has not established one, and the emptiest registry must never
    be the greenest.
    """
    return roots["verdict"] == COMPLETE


def blocking_cause(state: dict) -> str:
    """Why one node in a root's closure is not established, in the reviewer's vocabulary.

    `GAP` is the ADR-MCPRE-059 §28.5 terminal and it is DERIVED, never stored: a ratified
    claim with a real owner and no resolving support closure IS the gap. The other causes
    are not gaps — they are established claims whose evidence or review has gone stale, and
    sending a reviewer to look for missing architecture would waste the trip.
    """
    if state["deprecated"]:
        return "DEPRECATED: a withdrawn claim establishes nothing"
    if not state["supporting_units"]:
        return "GAP: ratified claim, real owner, no support closure — evidence does not exist"
    if not state["evidence_established"]:
        return "EVIDENCE: " + state["evidence"][1]
    review_state, reason = state["specification_review"]
    if review_state != REVIEWED:
        return f"SPECIFICATION REVIEW {review_state}: {reason}"
    review_state, reason = state["review"]
    if review_state == PREMISE_UNREVIEWED:
        return f"PREMISE REVIEW {review_state}: {reason}"
    if review_state != REVIEWED:
        return f"SEMANTIC REVIEW {review_state}: {reason}"
    return "DEPENDENCY: every local axis holds; a premise below it does not"


def _blocking_nodes(root: str, entries: dict[str, dict], assurance: dict[str, dict]) -> list[dict]:
    """The nodes of `root`'s `depends_on` closure that are not currently verified."""
    seen: set[str] = set()
    stack = [root]
    found: list[dict] = []
    while stack:
        node = stack.pop()
        if node in seen or node not in entries:
            continue
        seen.add(node)
        state = assurance.get(node)
        if state is None or state["currently_verified"]:
            continue
        found.append({"theorem": node, "cause": blocking_cause(state)})
        stack.extend(entries[node].get("depends_on", []))
    return sorted(found, key=lambda row: row["theorem"])


def root_completeness(theorems: dict, assurance: dict[str, dict]) -> dict:
    """Whether every DECLARED system root is established — ADR-MCPRE-059 §28.8.

    This is not evidence freshness and must never be reported as though it were. Freshness
    asks whether what the registry claims still describes the tree; completeness asks
    whether the claims the owner ratified as system promises are closed. A registry can be
    entirely fresh and entirely incomplete, and that combination is the normal state of a
    campaign in progress — which is precisely why an honest unresolved GAP must not fail
    ordinary CI (§28.8): a gate that punishes recording an obligation teaches people not to
    record it.

    The roots are read from the declaration, never inferred from the shape of the graph.

    For each unestablished root the whole `depends_on` closure is walked, so the report
    names the nodes that actually block it rather than only the root itself. A root three
    levels above a missing leaf is not informative on its own.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    roots = list(theorems.get("root_theorems", []))
    blocking = {
        root: _blocking_nodes(root, entries, assurance)
        for root in roots
        if not assurance.get(root, {}).get("currently_verified")
    }
    if not roots:
        verdict = UNDECLARED
    elif blocking:
        verdict = INCOMPLETE
    else:
        verdict = COMPLETE
    return {
        "verdict": verdict,
        "roots": roots,
        "established_roots": [r for r in roots if r not in blocking],
        "blocking": blocking,
    }
