# SPDX-License-Identifier: Apache-2.0
"""The one digest encoding every fingerprint uses, and the read-set recorder beside it.

`_fingerprint` composes the components; this module owns the two facts every component
shares: how bytes become a digest (`canonical_digest`, `digest_paths`) and how the files a
fingerprint read are recorded (`record`, `collect_reads`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextvars import ContextVar

import _tree

#: The read set of the fingerprint being computed under `collect_reads`, or None when nobody
#: is asking. Recorded where bytes are read rather than restated beside each component: a
#: second list of "what the fingerprint reads" is the drift
#: `scripts/verification_trigger_gate.py` exists to catch, so there is no second list.
_READS: ContextVar[set[str] | None] = ContextVar("fingerprint_reads", default=None)


def record(*paths: str) -> None:
    reads = _READS.get()
    if reads is not None:
        reads.update(paths)


def collect_reads(compute: Callable[[], object]) -> set[str]:
    """Run `compute` and return every path it recorded as read."""
    reads: set[str] = set()
    token = _READS.set(reads)
    try:
        compute()
    finally:
        _READS.reset(token)
    return reads


def _is_pattern(path: str) -> bool:
    return any(ch in path for ch in "*?[")


def _admitted_files(tree, pattern: str, tracked: frozenset[str] | None, tracked_only: bool):
    """The files `pattern` names that the digest takes, recording the tracked ones.

    An untracked file is digested unless `tracked_only` excludes it, and is never recorded:
    the read set describes the committed tree, as `_tracked_files` explains.
    """
    admitted = []
    for rel in tree.files(pattern):
        if tracked is None or rel in tracked:
            record(rel)
        elif tracked_only:
            continue
        admitted.append(rel)
    return admitted


def digest_paths(patterns: list[str], *, tracked_only: bool = False) -> dict[str, str]:
    """SHA-256 per file, keyed by repo-relative path, sorted.

    Content-addressed rather than mtime-based: a file restored to identical content is
    identical evidence, and a file whose bytes changed is not, regardless of timestamps.

    Every file digested is recorded in the read set if git tracks it; the read set
    describes the committed tree, as `_tracked_files` explains. A wildcard-free pattern
    is recorded even when nothing occupies it, because creating that file moves the
    digest. `tracked_only` inputs are the exception: they name alternatives — a
    `poetry.lock` where a project uses `uv` — that contribute nothing until tracked.
    """
    tree = _tree.current()
    tracked = tree.tracked() if tracked_only or _READS.get() is not None else None
    out: dict[str, str] = {}
    for pattern in sorted(patterns):
        if not tracked_only and not _is_pattern(pattern):
            record(pattern)
        for rel in _admitted_files(tree, pattern, tracked, tracked_only):
            out[rel] = "sha256:" + hashlib.sha256(tree.read(rel)).hexdigest()
    return out


def digest_tracked(patterns: list[str]) -> dict[str, str]:
    """`digest_paths`, restricted to what git tracks — for the glob-driven inputs."""
    return digest_paths(patterns, tracked_only=True)


def canonical_digest(value) -> str:
    """The one encoding every fingerprint in this module uses.

    Single function rather than an inlined `json.dumps` per call site, because "how a
    fingerprint is encoded" is exactly the fact that must not have two implementations: two
    encoders that agree today and diverge later would make two records incomparable while
    both look well-formed.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assumption_digest(entry: dict) -> str:
    """A digest of WHAT AN ASSUMPTION TRUSTS — its whole registry entry.

    Exposed because two axes read it: a unit's `trusted_assumptions` component, and the
    assumption review axis, which is fresh only while the entry a reviewer ratified still
    hashes the same.
    """
    return canonical_digest(entry)
