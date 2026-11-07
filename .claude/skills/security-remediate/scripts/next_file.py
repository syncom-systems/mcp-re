#!/usr/bin/env python3
"""next_file.py — worklist selector for the security-remediate loop.

Reads the file-keyed finding ledger and returns the next file to remediate,
leaf-first (dependencies before dependents, so a fixed dependency is already
clean when its dependents are reached). Pure stdlib — it is analysis tooling,
not production code.

Output (JSON) for the outer driver:
  {
    "exhausted": bool,             # no actionable (open/regression) findings left
    "file": "<path>" | null,       # the file to work next
    "related": ["<path>", ...],    # reverse-dep set to re-scan with the file
    "findings": [ {finding...} ],  # all open/regression findings on that file
    "blocked": {"escalated": n, "exhausted": n},  # findings needing a human
    "remaining_open_files": n
  }

`exhausted: true` with blocked > 0 means: nothing the loop can auto-progress;
only human-gated findings remain.

Ledger: one JSON object per line (see ledger.py for the status taxonomy). Required
fields per record: id, path (or file), severity, status, title, category.

Deps (optional, --deps): {"<file>": ["<file it imports>", ...], ...}. When given,
files are ordered topologically (imports first). The reverse-dep "related" set is
derived from it. Without it, ordering falls back to severity-then-path and
`related` is empty (the inner loop then re-scans only the file itself).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _next_file_select import Scope, select  # noqa: E402,F401 — the tests import select and Scope from here


def _arguments() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Select the next file for the security-remediate loop.")
    ap.add_argument("--ledger", required=True, help="path to finding-ledger.jsonl")
    ap.add_argument("--deps", default=None, help="optional {file: [imported files]} JSON for leaf-first order")
    ap.add_argument("--json", action="store_true", help="emit JSON (default)")
    ap.add_argument("--top", type=int, default=1,
                    help="also return the next N files as `batch`, for fan-out evaluation")
    ap.add_argument("--files-only", action="store_true",
                    help="print just the batch's file paths, one per line")
    ap.add_argument("--rounds", default="",
                    help="comma-separated live rounds (e.g. 2026-09-15@r11,2026-09-22@r12); "
                         "findings seen in none of them are ignored")
    ap.add_argument("--order", default=None,
                    help="JSON campaign order: a list of paths or of {\"file\": path} rows")
    return ap.parse_args()


def main() -> int:
    args = _arguments()
    rounds = {r.strip() for r in args.rounds.split(",") if r.strip()} or None
    result = select(args.ledger, args.deps, args.top, Scope(rounds, args.order))
    if args.files_only:
        for b in result.get("batch", []):
            print(b["file"])
        return 0
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
