# SPDX-License-Identifier: Apache-2.0
"""The ratchet's verdict: measured tokens against the registered debt."""

from __future__ import annotations

from pathlib import Path

from _doc_path.config import REGISTRY
from _doc_path.registry import load_registry
from _doc_path.scan import measure, scanned_count


def _row_errors(rel: str, hits: list[str], row: dict | None) -> list[str]:
    """What is wrong with one measured file against its registry row, if anything."""
    listing = [f"    {h}" for h in hits]
    if row is None:
        return [f"{rel}: {len(hits)} unresolved token(s), and no registry entry"] + listing
    baseline = row.get("dead_tokens", 0)
    if len(hits) > baseline:
        return [
            f"{rel}: {len(hits)} unresolved token(s), registered at {baseline} — "
            f"a registry entry pins a file, it does not exempt one"
        ] + listing
    if len(hits) < baseline:
        return [
            f"{rel}: {len(hits)} unresolved token(s), registered at {baseline} — "
            f"lower the entry to {len(hits)}"
        ]
    return []


def verdict(root: Path, registry: Path = REGISTRY) -> int:
    measured = measure(root)
    rows, errors = load_registry(registry, root)
    for rel, hits in sorted(measured.items()):
        errors += _row_errors(rel, hits, rows.get(rel))
    errors += [
        f"{rel}: registered, but resolves cleanly — remove the entry"
        for rel in sorted(rows)
        if rel not in measured
    ]
    scanned = scanned_count(root)
    if errors:
        print(f"doc-path gate: FAIL ({scanned} in-scope files read)")
        for e in errors:
            print(f"  {e}")
        return 1
    print(
        f"doc-path gate: PASS ({scanned} in-scope files read, "
        f"{sum(len(v) for v in measured.values())} registered token(s), none new)"
    )
    return 0
