# SPDX-License-Identifier: Apache-2.0
"""Every direct thread spawn in production library code that nobody reviewed."""

from __future__ import annotations

from pathlib import Path

from _owned_worker.config import ALLOWED, OWNER_MODULE
from _owned_worker.scan import crates, production_spawns
from _rust_source import crate_sources


def _allowed_problems(rel: str, sites: list[int]) -> list[str]:
    """The exemption is for the reviewed sites, not for the file. A count that no longer
    matches means a thread nobody argued for, or a reason that has outlived the code it
    describes."""
    expected, reason = ALLOWED[rel]
    if len(sites) == expected:
        return []
    at = ", ".join(f":{line}" for line in sites) or "none"
    return [
        f"{rel} is allowlisted for {expected} reviewed spawn site(s) "
        f"({reason.strip()}) but has {len(sites)} ({at}). Route the new "
        "thread through `managed_worker::WorkerSet::spawn`, or update "
        "this gate's entry with the count and the reason the extra "
        "thread is sound."
    ]


def _direct_problems(rel: str, sites: list[int]) -> list[str]:
    return [
        f"{rel}:{line} spawns a thread directly. A runtime worker must be "
        "started through `managed_worker::WorkerSet::spawn`, which owns the "
        "handle; if this thread is genuinely not a runtime worker, add the "
        "file to ALLOWED in this gate with its site count and the reason."
        for line in sites
    ]


def _file_problems(root: Path, crate: Path, src_path: Path) -> list[str]:
    if src_path.relative_to(crate).as_posix() == OWNER_MODULE:
        return []
    rel = src_path.relative_to(root).as_posix()
    sites = production_spawns(src_path.read_text(encoding="utf-8"))
    if rel in ALLOWED:
        return _allowed_problems(rel, sites)
    return _direct_problems(rel, sites)


def check(root: Path) -> list[str]:
    return [
        problem
        for crate in crates(root)
        for src_path in crate_sources(crate / "src")
        for problem in _file_problems(root, crate, src_path)
    ]
