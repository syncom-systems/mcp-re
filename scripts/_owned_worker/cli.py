# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the real repository."""

from __future__ import annotations

from _owned_worker.check import check
from _owned_worker.config import ALLOWED, OWNER_MODULE, REPO
from _owned_worker.scan import crates


def verdict() -> int:
    problems = check(REPO)
    if problems:
        print("owned-worker gate: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"owned-worker gate: OK — {len(crates(REPO))} crates scanned, no direct thread "
        f"spawn in production library code outside {OWNER_MODULE}, except "
        f"{sum(sites for sites, _ in ALLOWED.values())} counted sites in "
        f"{len(ALLOWED)} files that each name a reason."
    )
    return 0
