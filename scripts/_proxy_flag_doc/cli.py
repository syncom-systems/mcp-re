# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the real repository."""

from __future__ import annotations

import sys

from _proxy_flag_doc.check import check
from _proxy_flag_doc.config import REPO, TOOLS
from _proxy_flag_doc.scan import doc_files


def report(skipped: list[str], problems: list[str]) -> int:
    for rel in skipped:
        print(f"skipped (declares itself superseded): {rel}")
    if problems:
        print("cli-flag documentation gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"cli-flag documentation gate: every documented flag exists for the tool whose "
        f"command line it is on ({', '.join(t.binary for t in TOOLS)}; "
        f"{len(doc_files(REPO))} documents scanned, {len(skipped)} skipped)"
    )
    return 0


def verdict() -> int:
    skipped: list[str] = []
    problems = check(REPO, skipped)
    return report(skipped, problems)
