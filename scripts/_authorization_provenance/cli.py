# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree."""

from __future__ import annotations

import sys

from _authorization_provenance.config import REPO
from _authorization_provenance.sources import check


def judge() -> int:
    problems, examined = check(REPO)
    if examined == 0:
        print(
            "authorization-provenance gate: FAIL — examined nothing. An empty scope is a "
            "broken gate, not a clean tree.",
            file=sys.stderr,
        )
        return 1
    if problems:
        print(f"authorization-provenance gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"authorization-provenance gate: OK — {examined} production module(s) examined; the "
        f"authorization authority reads its action from the signed body, takes the "
        f"ADR-MCPRE-064 binding whole, keeps every product sealed, and the dispatch "
        f"consumes a body only a decision can release."
    )
    return 0
