# SPDX-License-Identifier: Apache-2.0
"""What the declared theorem edges alone derive: the roots and the structurally supported set.

Read-only over a validated registry document; `_theorems` validates it.
"""

from __future__ import annotations


def root_theorems(doc: dict) -> list[str]:
    """The declared system roots, in declaration order. Never inferred (§28.1)."""
    return list(doc.get("root_theorems", []))


def structurally_supported_theorems(doc: dict) -> set[str]:
    """The theorems whose support closure RESOLVES, by the declared edges alone.

    A theorem is structurally supported only if some review unit supports it AND every
    theorem it depends on is structurally supported. A theorem with no supporting unit is
    therefore not structurally supported — it is a stated claim awaiting evidence, and the
    difference is the whole reason the layer exists. A deprecated theorem supports nothing:
    it is retained so historical evidence stays resolvable, not so it can carry a live
    closure.

    This is a structural property and it is named as one. It says the closure resolves to
    real units and real premises; it says NOTHING about whether their evidence ran, is
    fresh, is BLOCKED, or rests on an assumption whose review has gone dirty. A unit that
    merely exists satisfies this function.

    `established` is deliberately not the word, and is reserved for the later conjunction —
    structural support AND fresh unit evidence AND established dependencies AND fresh
    specification review AND fresh assumption review — which T2 makes derivable and T3
    displays. A name that claims assurance this layer cannot see is exactly the over-read
    ADR-MCPRE-059 exists to prevent, and it would be read as proof the moment it reached a
    generated human view.
    """
    entries = {entry["id"]: entry for entry in doc.get("theorem", [])}
    supported = {
        tid
        for tid, entry in entries.items()
        if entry.get("supported_by") and not entry.get("replaced_by")
    }
    changed = True
    while changed:
        changed = False
        for tid in sorted(supported):
            deps = entries[tid].get("depends_on", [])
            if any(dep not in supported for dep in deps):
                supported.discard(tid)
                changed = True
    return supported


def unsupported_theorems(doc: dict) -> list[str]:
    """Declared, live theorems whose support closure does not resolve."""
    supported = structurally_supported_theorems(doc)
    return sorted(
        entry["id"]
        for entry in doc.get("theorem", [])
        if entry["id"] not in supported and not entry.get("replaced_by")
    )
