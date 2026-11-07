# SPDX-License-Identifier: Apache-2.0
"""The trust-boundary component of a unit fingerprint.

`trust-boundaries.toml` caps how far a unit may be promoted, so the boundaries a unit
crosses are part of what its claim means. This module loads the declared boundaries once per
registry text and tree, and digests the ones a unit's paths cross.
"""

from __future__ import annotations

import hashlib

import _registries
import _tree
from _boundary_crossings import expand_paths
from _fingerprint_digest import canonical_digest
from _trust_boundaries import load_trust_boundaries


def declared_boundaries() -> dict:
    """The declared trust boundaries, loaded and checked once per registry text and tree."""
    text = _tree.text(_registries.relative("trust-boundaries"))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return _tree.current().memo(f"trust-boundaries:{digest}", load_trust_boundaries)


def _boundary_files(patterns: tuple[str, ...]) -> frozenset[str]:
    """The files a boundary's patterns name, walked once per tree."""
    return _tree.current().memo(
        f"boundary:{patterns!r}", lambda: frozenset(expand_paths(list(patterns)))
    )


def governing_boundaries(unit: dict, boundaries: dict) -> dict[str, str]:
    """The declared trust boundaries this unit's paths cross, by id and content digest.

    `trust-boundaries.toml` decides how far a unit may be promoted: a theorem about code on
    this side of a boundary says nothing about the other side, so
    `max_class_without_assumption` is what keeps a proof's meaning honest across it. That
    cap participated in NO fingerprint. Widening it — or deleting the boundary, or narrowing
    its `paths` so it stops covering a unit — relaxed the rule and invalidated nothing, so
    every claim above it kept deriving FRESH while the argument beneath it had changed.

    The digest covers the whole entry, not the cap alone, because each field can weaken the
    reading on its own: `paths` decides WHICH units the cap binds, `beyond` states what is
    being trusted, and `kind` is how a reader classifies the trust. Only the boundaries a
    unit actually crosses are included, so a change to an unrelated boundary does not dirty
    the whole tree — the same relation `boundary_class_violations` uses to decide the rule.
    """
    unit_files = expand_paths(unit["paths"])
    crossed: dict[str, str] = {}
    for boundary in boundaries.get("boundary", []):
        if not unit_files & _boundary_files(tuple(boundary["paths"])):
            continue
        crossed[boundary["id"]] = canonical_digest(
            {
                "kind": boundary.get("kind"),
                "beyond": boundary.get("beyond"),
                "max_class_without_assumption": boundary.get(
                    "max_class_without_assumption"
                ),
                "paths": sorted(boundary["paths"]),
            }
        )
    return dict(sorted(crossed.items()))
