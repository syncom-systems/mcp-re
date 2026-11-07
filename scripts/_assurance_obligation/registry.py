# SPDX-License-Identifier: Apache-2.0
"""The registry file, the measured population, and the unit paths at this tree and at the base."""

from __future__ import annotations

from pathlib import Path

import _ratchet
import _registries

from _assurance_obligation.config import (
    KEYS,
    OPTIONAL,
    REGISTRY_REL,
    REPO,
    REVIEWED,
    STATUSES,
    UNITS_REL,
)

#: The register's shape. `_ratchet` checks it, the `review_ref` rule included;
#: `load_registry` adds the one field rule that is this registry's own.
SCHEMA = _ratchet.Schema(
    table="obligation",
    key="unit",
    required=frozenset(KEYS - OPTIONAL),
    fields=frozenset(KEYS),
    statuses=STATUSES,
    reviewed=frozenset(REVIEWED),
)


def owing() -> dict[str, dict]:
    """Every `tested` proposition that owes a falsifier now, with the severities it owes at.

    The one authority on WHO OWES is `_assurance_graph`, deliberately: the loader and
    `review` read the same derivation, and a gate that recomputed severity its own way could
    hold a baseline against a population nobody else agrees on.
    """
    import _assurance_graph as graph
    import _manifest
    import _theorems

    units = _manifest.load_verification()
    theorems = _theorems.load_theorems({unit["id"] for unit in units["unit"]})
    return graph.unmet_obligations(theorems, units)


def current_unit_paths() -> dict[str, set[str]]:
    """Each unit's declared `paths` as this tree has them."""
    import _manifest

    return {
        unit["id"]: set(unit.get("paths", []))
        for unit in _manifest.load_verification().get("unit", [])
    }


def obligations(root: Path = REPO) -> _ratchet.Register:
    return _ratchet.Register(REGISTRY_REL, SCHEMA, root)


def load_registry(register: _ratchet.Register | None = None) -> dict[str, dict]:
    """The registry, validated strictly — an unknown key is a failure, not an ignored field.

    A missing file is an empty registry rather than an error, and that is not a loophole:
    with no rows, every owing proposition is unregistered and fails immediately.
    """
    register = register or obligations()
    try:
        rows = register.current()
    except _ratchet.RegisterError as exc:
        raise ValueError(str(exc)) from exc
    problems = register.problems(rows) + [
        f"{unit}: `obligation` is empty. A row names the obligation it owes, or the registry "
        f"cannot say what closing the row would mean."
        for unit, row in sorted(rows.items())
        if not str(row.get("obligation", "x")).strip()
    ]
    if problems:
        raise ValueError(f"{register.rel}: " + "; ".join(problems))
    return rows


def severity_rank(name: str) -> int:
    """The severity's rank in the one declared vocabulary.

    Imported rather than restated: `_evidence_class` is the single authority on the closed
    vocabulary and its order, and a second copy here would let the gate compare severities
    the graph does not recognise.
    """
    from _evidence_class import SEVERITY_ORDER

    return SEVERITY_ORDER[name]


def base_unit_paths(base: str, repo: Path = REPO) -> dict[str, set[str]] | None:
    """Each unit's declared `paths` at `base`, or None when that revision is unavailable.

    UNAVAILABLE IS NOT EMPTY, the rule `_ratchet`'s baseline states keep: an empty mapping would
    read as "the predecessor declared no paths", under which every successor's paths are
    trivially NOT a subset and a legitimate succession fails — or, with the test inverted,
    every one passes. Neither is a fact about the tree.
    """
    try:
        text = _registries.text_at("verification", base, repo)
    except _registries.ManifestError:
        return None
    if text is None:
        return None
    doc = _registries.parse(text, f"{base}:{UNITS_REL}")
    return {unit["id"]: set(unit.get("paths", [])) for unit in doc.get("unit", [])}
