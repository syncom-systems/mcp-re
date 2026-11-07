# SPDX-License-Identifier: Apache-2.0
"""Turning a gazelle diff into the drift the gate fails on."""

from __future__ import annotations

from _bazel_gazelle.analyze import analyze_file
from _bazel_gazelle.config import ALLOW_TRACKED_DRIFT, ALLOWLIST
from _bazel_gazelle.diff import parse_per_file


def classify(
    diff: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], set[str]]:
    """`(missing targets, missing edges, tracked drift seen)` for a gazelle diff.

    Targets and edges are `(file, name-or-label)`. A proposed target the ALLOWLIST names
    is not drift; one of those that is tracked drift is reported back so the pass line
    keeps naming it.
    """
    missing_targets: list[tuple[str, str]] = []
    missing_edges: list[tuple[str, str]] = []
    tracked_hits: set[str] = set()
    for path, lines in parse_per_file(diff).items():
        new_names, inserted = analyze_file(lines)
        missing_targets.extend((path, n) for n in new_names if n not in ALLOWLIST)
        tracked_hits.update(n for n in new_names if n in ALLOW_TRACKED_DRIFT)
        missing_edges.extend((path, edge) for edge in inserted)
    return missing_targets, missing_edges, tracked_hits
