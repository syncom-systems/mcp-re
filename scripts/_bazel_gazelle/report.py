# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the diff gazelle would apply."""

from __future__ import annotations

from _bazel_gazelle.classify import classify
from _bazel_gazelle.config import ALLOW_TRACKED_DRIFT
from _bazel_gazelle.diff import run_gazelle_diff


def _print_pass(tracked_hits: set[str]) -> None:
    print("bazel-gazelle-gate: PASS — no unmanaged semantic drift.")
    if tracked_hits:
        print("  (tracked known drift still allowlisted:)")
        for n in sorted(tracked_hits):
            print(f"    - {n}: {ALLOW_TRACKED_DRIFT[n]}")


def _print_targets(missing_targets: list[tuple[str, str]]) -> None:
    if not missing_targets:
        return
    print("Missing Bazel targets (cargo builds them; Bazel does not):")
    for path, name in sorted(missing_targets):
        print(f"    {path}: {name}")
    print()


def _print_edges(missing_edges: list[tuple[str, str]]) -> None:
    if not missing_edges:
        return
    print("Missing / unexpected dep edges (a `use` implies them; BUILD omits):")
    for path, edge in sorted(set(missing_edges)):
        print(f"    {path}: {edge}")
    print()


def _print_fail(
    missing_targets: list[tuple[str, str]], missing_edges: list[tuple[str, str]]
) -> None:
    print("bazel-gazelle-gate: FAIL — unmanaged semantic drift detected.\n")
    _print_targets(missing_targets)
    _print_edges(missing_edges)
    print("Fix: add the target/edge to the crate's BUILD.bazel (see the gazelle")
    print("diff: `bazel run //:gazelle -- -mode diff`), or, if it is an intentional")
    print("exception, add it to the categorized ALLOWLIST in this script with a reason.")


def main() -> int:
    missing_targets, missing_edges, tracked_hits = classify(run_gazelle_diff())
    if not (missing_targets or missing_edges):
        _print_pass(tracked_hits)
        return 0
    _print_fail(missing_targets, missing_edges)
    return 1
