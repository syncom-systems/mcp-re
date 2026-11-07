#!/usr/bin/env python3
"""progress.py — the tailable record of a long remediation run.

A lane that runs for hours or days is otherwise silent. This is not only
observability: the risk in a long campaign is not one bad file, it is a bad
POLICY applied consistently — an evaluator that closes too freely, a worker whose
anchors keep missing — discovered at file 600 instead of file 20. The log is what
makes that catchable, and `stats` is what makes it measurable.

Writes ONE file: <log>.jsonl, the append-only record, one line per stage event.
There is no second, human-formatted copy: nothing read it, and a view that can
drift from the record is a liability. `render` prints the human view on demand
and `watch` tails it for anomalies — both read the JSONL.

EVERY ROLE APPENDS ITS OWN EVENT. A single writer would leave silent holes
whenever an agent dies mid-stage; per-role events also give stage granularity
instead of one line an hour. `reconcile` closes the gap the other way: a file
with no terminal event gets a `lost` line, so a crash is visible as a crash
rather than as a shorter log.

Subcommands:
  append     one stage event (role, outcome, counts)
  close      a terminal disposition — its own verbose line, because
             false-positive / premise are the irreversible decisions
  reconcile  synthesize `lost` for files that never reached a terminal event
  stats      calibration: closure rate, work rate, escalation rate, streaks
  watch      read JSONL on stdin, emit ONLY anomaly lines (for Monitor)
  render     print the human view of the JSONL
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _progress_cli import build_parser  # noqa: E402
from _progress_journal import SCHEMA_VERSION, SNAPSHOT_EVENTS, TERMINAL_EVENTS  # noqa: E402,F401
from _progress_write import cmd_append, cmd_close  # noqa: E402,F401 — check.py and dispose.py call them


def main() -> int:
    a = build_parser(__doc__.splitlines()[0]).parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
