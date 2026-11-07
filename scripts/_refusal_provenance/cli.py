# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree."""

from __future__ import annotations

from _refusal_provenance.check import check
from _refusal_provenance.sources import workspace_rust_files

MINIMUM_FILES = 100


def judge() -> int:
    examined = len(workspace_rust_files())
    if examined < MINIMUM_FILES:
        print(
            f"refusal-provenance gate: FAIL — the workspace walk found {examined} shipped "
            f"Rust file(s). The scope has collapsed; a clean pass over almost nothing is "
            f"worse than a failure."
        )
        return 1
    problems = check()
    if problems:
        print("refusal-provenance gate: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"refusal-provenance gate: OK — {examined} shipped Rust file(s) examined; "
        "a refusal carries its authority rather than a rendered "
        "token, the authorization branch survives the stage boundary intact, PolicyError has "
        "no route into the Core taxonomy, the cause algebra is exhaustive, the record states "
        "each authority's outcome in its own coordinate, no rejection reason can be built "
        "from a string, and every production refusal site is inside the exchange lifecycle "
        "or is the one declared pre-exchange transport refusal."
    )
    return 0
