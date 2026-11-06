# SPDX-License-Identifier: Apache-2.0
"""Record-level admission primitives shared by every registry loader.

Strict unknown-key refusal, required keys, and the one place a registry is read from the
current source tree. An unknown key is a validation FAILURE, not a field that is silently
ignored (ADR-MCPRE-059, "Authoritative manifest").
"""

from __future__ import annotations

from pathlib import Path

from _registries import ManifestError
from _registries import REPO_ROOT
import _registries
import _tree


def load_registry(path: Path) -> dict:
    """The registry at `path`, read from the current source tree."""
    rel = path.relative_to(REPO_ROOT).as_posix()
    tree = _tree.current()
    if not tree.is_file(rel):
        raise ManifestError(f"{rel}: missing")
    return _registries.parse(tree.read(rel).decode("utf-8"), rel)


#: Keys a unit may no longer declare because the fact has ONE authority elsewhere. Named
#: rather than merely unknown, for the reason `_theorems._DUPLICATED_AUTHORITY` exists: the
#: generic message sends a reader looking for a typo when the real answer is "that fact is
#: declared elsewhere, and declaring it twice is how the two disagree".
_MOVED_AUTHORITY = {
    "consumed_contracts": (
        "verification.toml [[edge]].contract — derived from the incoming CONTRACT_CONSUMES "
        "edges. A unit does not declare what it consumes twice: the edge already names the "
        "contract and the producer that exports it, and an independently authored field is "
        "a second answer that nothing reconciles"
    ),
}


def reject_unknown(where: str, got, allowed: set[str]) -> None:
    """Refuse a key `allowed` does not name, and name the new authority of a moved one."""
    moved = sorted(set(got) & set(_MOVED_AUTHORITY))
    if moved:
        raise ManifestError(
            f"{where}: {moved[0]!r} is no longer declared here. Its authority is "
            f"{_MOVED_AUTHORITY[moved[0]]}."
        )
    unknown = sorted(set(got) - allowed)
    if unknown:
        raise ManifestError(
            f"{where}: unknown key(s) {unknown}. "
            f"Unknown keys fail validation rather than being ignored — a mistyped "
            f"security declaration must not read as an absent one."
        )


def require(where: str, got: dict, required: set[str]) -> None:
    """Refuse a record that lacks a key `required` names."""
    missing = sorted(required - set(got))
    if missing:
        raise ManifestError(f"{where}: missing required key(s) {missing}")
