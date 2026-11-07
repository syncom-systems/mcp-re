# SPDX-License-Identifier: Apache-2.0
"""Which typed premises each declared root ultimately rests on — N5: the composition of the
`depends_on` closure of a root with the units that support each theorem and the premises
scoped to each unit."""

from __future__ import annotations

from dataclasses import dataclass

from _premise_model import PREMISE_CLASSES, is_live, is_model_registration


def _closure(root: str, entries: dict) -> set[str]:
    """Every theorem the root transitively depends on, including itself."""
    seen: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node in seen or node not in entries:
            continue
        seen.add(node)
        stack.extend(entries[node].get("depends_on", []))
    return seen


def _supports(theorems: dict) -> dict[str, set[str]]:
    # `supported_by` carries `unit://<id>` URIs and `scope` carries the same form, so both
    # sides are reduced to the bare id here. Comparing one against the other verbatim
    # produced an empty intersection for all twelve roots and reported "no root rests on any
    # premise" — a composition that is silently EMPTY reads exactly like a clean result,
    # which is why `test_premise_class` asserts the count is non-zero rather than only that
    # the function runs.
    return {
        row["id"]: {str(u).removeprefix("unit://") for u in row.get("supported_by", [])}
        for row in theorems.get("theorem", [])
    }


def _scoped_by_unit(assumptions: dict) -> dict[str, set[str]]:
    scoped: dict[str, set[str]] = {}
    for entry in assumptions.get("assumption", []):
        if not is_live(entry):
            continue
        for unit in _unit_targets(entry):
            scoped.setdefault(unit, set()).add(entry["id"])
    return scoped


def _unit_targets(entry: dict) -> list[str]:
    targets = [str(target) for target in entry.get("scope", [])]
    return [text[len("unit://") :] for text in targets if text.startswith("unit://")]


@dataclass(frozen=True)
class _Composition:
    """The three joins a root's premises are read through."""

    entries: dict
    supports: dict[str, set[str]]
    scoped: dict[str, set[str]]
    by_id: dict

    def reached(self, root: str) -> set[str]:
        """The premises scoped to any unit supporting any theorem `root` stands on."""
        reached: set[str] = set()
        for theorem in _closure(root, self.entries):
            for unit in self.supports.get(theorem, set()):
                reached |= self.scoped.get(unit, set())
        return reached

    def rows(self, root: str) -> dict[str, list[str]]:
        """The premises `root` rests on, by class, registrations dropped."""
        rows: dict[str, list[str]] = {name: [] for name in PREMISE_CLASSES}
        for asm_id in sorted(self.reached(root)):
            if not is_model_registration(self.by_id[asm_id]):
                rows[self.by_id[asm_id]["premise_class"]].append(asm_id)
        return rows


def roots_reaching_premises(theorems: dict, verification: dict, assumptions: dict) -> dict:
    """Which typed premises each declared root ultimately rests on — N5.

    THE COMPOSITION, and it is the whole of what §7 found missing. Both halves already
    existed and nothing joined them: `_catalogue_views.assumption_consumers` derives
    *scope → unit → theorem* at render time, and `_review.root_completeness` walks the
    `depends_on` closure — so the registry could say which theorem an assumption reaches and
    which theorems a root stands on, and could not answer the question anybody actually
    asks, which spans both.

    Derived here, never stored. Storing the `consumed_by` direction is exactly what
    ADR-MCPRE-059 §8.2 forbids, and a second stored authority over reachability would be
    free to disagree with the two live ones.

    Returns `{root_id: {premise_class: [assumption ids]}}`, classes in vocabulary order.
    """
    composition = _Composition(
        entries={row["id"]: row for row in theorems.get("theorem", [])},
        supports=_supports(theorems),
        scoped=_scoped_by_unit(assumptions),
        by_id={entry["id"]: entry for entry in assumptions.get("assumption", [])},
    )
    return {str(root): composition.rows(str(root)) for root in theorems.get("root_theorems", [])}
