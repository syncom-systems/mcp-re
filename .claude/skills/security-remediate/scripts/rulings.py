#!/usr/bin/env python3
"""rulings.py — the human decision queue for the security-remediate lane.

An escalation is not a unit of work for a human: several findings usually wait on
ONE decision, and evaluators mark the duplicates as they go. This renders the
`escalated` rows as a ruling queue — grouped by the row's `ruling_id` across files
(an escalation without one is grouped by file), duplicates folded under the finding
that carries the decision — so the orchestrator hands over N decisions, not N
findings. A `ruling_id` prefixed `owner-signature:` is not a choice: one remedy
survives, but it lands on an owner-ratified surface, so it is listed apart as a
ratification.

Async by design: the lane never blocks on this. It records escalations, keeps
working other files, and this file is what the human answers between ticks.

Usage:
  rulings.py --ledger <ledger.jsonl> [--out RULINGS.md] [--since <round>]
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _rulings_queue import build_queue, load_blocked_on, load_rows  # noqa: E402
from _rulings_render import decision_count, render  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--since", default=None, help="only escalations first seen in this round")
    ap.add_argument("--packages", default=None,
                    help="evaluator work-package dir; its per-file `blocked_on` states THE decision, "
                         "which is a truer unit than one decision per escalated finding")
    a = ap.parse_args()

    queue = build_queue(load_rows(a.ledger), a.since)
    blocked_on = load_blocked_on(a.packages)
    out = render(queue, blocked_on)
    if not a.out:
        print(out)
        return 0
    with open(a.out, "w") as fh:
        fh.write(out)
    print("wrote %s: %d escalations -> %d decisions + %d ratifications over %d files"
          % (a.out, len(queue.escalated), decision_count(queue, blocked_on),
             len(queue.signature), len(queue.files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
