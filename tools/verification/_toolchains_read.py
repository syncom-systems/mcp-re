# SPDX-License-Identifier: Apache-2.0
"""Reading the toolchain lock: the parsed document, and which of its pins are unresolved."""

from __future__ import annotations

from pathlib import Path

import _registries
from _registries import REPO_ROOT
from _registries import ManifestError

WHERE = "toolchains.lock.toml"
STATES = frozenset({"resolved", "unresolved"})


def path(root: Path = REPO_ROOT) -> Path:
    """The lock file, for a reader that edits or digests its bytes."""
    return _registries.path("toolchains", root)


def _check_sub_tables(name: str, entry: dict) -> None:
    for sub_name, sub in entry.items():
        if isinstance(sub, dict) and sub.get("state") not in STATES:
            raise ManifestError(
                f"{WHERE}: [{name}.{sub_name}] state must be 'resolved' or 'unresolved'"
            )


def _check_entry(name: str, entry: object) -> None:
    if not isinstance(entry, dict):
        raise ManifestError(f"{WHERE}: [{name}] must be a table")
    state = entry.get("state")
    if state not in STATES:
        raise ManifestError(
            f"{WHERE}: [{name}] state must be 'resolved' or 'unresolved', got "
            f"{state!r}. A tool with no state is a tool of unknown identity."
        )
    _check_sub_tables(name, entry)


def load(root: Path = REPO_ROOT) -> dict:
    """The lock parsed, with every table's `state` checked.

    A table or sub-table with no `state`, or with any value but `resolved` and
    `unresolved`, is a tool of unknown identity and is refused here rather than read as
    either.
    """
    doc = _registries.document("toolchains", root, required=True)
    if "schema_version" not in doc:
        raise ManifestError(f"{WHERE}: missing required key(s) ['schema_version']")
    for name, entry in doc.items():
        if name != "schema_version":
            _check_entry(name, entry)
    return doc


def _unresolved_in(name: str, entry: dict) -> list[str]:
    out = [name] if entry.get("state") == "unresolved" else []
    out += [f"{name}.{sub_name}" for sub_name, sub in entry.items()
            if isinstance(sub, dict) and sub.get("state") == "unresolved"]
    return out


def unresolved_pins(toolchains: dict) -> list[str]:
    """Every toolchain identity that is not pinned, as dotted names.

    An unresolved pin means the tool's identity is unknown, and unknown is dirty. The
    lanes that depend on it refuse to run rather than running against whatever is on
    PATH — a proof checked by an unknown prover is not evidence.
    """
    out: list[str] = []
    for name, entry in toolchains.items():
        if name != "schema_version" and isinstance(entry, dict):
            out += _unresolved_in(name, entry)
    return sorted(out)
