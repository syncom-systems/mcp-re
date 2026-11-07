# SPDX-License-Identifier: Apache-2.0
"""Loading and validating the declared trust boundaries."""

from __future__ import annotations

from _unit_rules import CLASSES
from _record_rules import reject_unknown, require
from _registries import ManifestError
import _record_rules
import _registries
import _tree


TRUST_BOUNDARIES_TOML = _registries.path("trust-boundaries")


_BOUNDARY_KEYS = {
    "id",
    "description",
    "kind",
    "paths",
    "beyond",
    "max_class_without_assumption",
}


def load_trust_boundaries(*, tree_checks: bool = True) -> dict:
    """Load and validate the declared trust boundaries."""
    doc = _record_rules.load_registry(TRUST_BOUNDARIES_TOML)
    where = "trust-boundaries.toml"
    reject_unknown(where, doc, {"schema_version", "boundary"})
    require(where, doc, {"schema_version"})
    for index, entry in enumerate(doc.get("boundary", [])):
        _validate_boundary(f"{where} [[boundary]] #{index}", entry, tree_checks)
    return doc


def _validate_boundary(bwhere: str, entry: dict, tree_checks: bool) -> None:
    """Every admission rule one `[[boundary]]` record owes, in the order they are checked."""
    reject_unknown(bwhere, entry, _BOUNDARY_KEYS)
    require(bwhere, entry, {"id", "description", "kind", "paths", "beyond"})
    cls = entry.get("max_class_without_assumption")
    if cls is not None and cls not in CLASSES:
        raise ManifestError(f"{bwhere}: max_class_without_assumption {cls!r} invalid")
    if tree_checks:
        _require_boundary_paths_resolve(bwhere, entry)


def _require_boundary_paths_resolve(bwhere: str, entry: dict) -> None:
    """Every path a boundary declares matches at least one file in the current tree."""
    for pattern in entry.get("paths", []):
        # A boundary path that matches nothing SILENTLY NARROWS the boundary. Unlike a
        # unit path, `expand_paths` globs these, so a stale entry raises nothing and the
        # code it used to name simply stops being inside the boundary — and
        # `boundary_class_violations` stops seeing units that cross it. That is an
        # over-read produced by a rename, which is exactly what happened when MCPRE-175
        # turned `pkcs11_keysource.rs` and `async_replay.rs` into owner subtrees.
        if not _tree.current().files(str(pattern)):
            raise ManifestError(
                f"{bwhere}: path {pattern!r} matches nothing. A boundary that names no "
                f"file bounds no unit's class, so a stale entry reads as a registered "
                f"boundary while trusting the code it used to cover nowhere."
            )
