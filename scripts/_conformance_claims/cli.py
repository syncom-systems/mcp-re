# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the real repository."""

from __future__ import annotations

from _conformance_claims.check import check
from _conformance_claims.config import GUIDE, REPO
from _conformance_claims.corpus import parse_rows


def verdict() -> int:
    failures = check(REPO)
    if failures:
        print("conformance-claims gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    rows, _ = parse_rows((REPO / GUIDE).read_text(encoding="utf-8"))
    print(
        f"conformance-claims gate: OK — {len(rows)} advertised categories, each with a "
        "corpus and a harness that reaches it"
    )
    return 0
