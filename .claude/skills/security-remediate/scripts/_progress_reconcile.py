"""`reconcile`: synthesize `lost` / `not-started` where no terminal event exists."""
from __future__ import annotations

import json

from _progress_journal import TERMINAL_EVENTS, append_event, attempts_of, load


def _classify(attempts: dict) -> tuple[list, set, set]:
    """(lost attempts, files with a terminal event, files that started)."""
    lost: list = []
    terminal_files: set = set()
    started_files: set = set()
    for key, evs in attempts.items():
        files = {e.get("file", "") for e in evs if e.get("file")}
        started_files |= files
        if any(e.get("event") in TERMINAL_EVENTS for e in evs):
            terminal_files |= files
        else:
            lost.append((key, sorted(files)))
    return lost, terminal_files, started_files


def _append_lost(log: str, lost: list) -> None:
    for key, files in sorted(lost, key=lambda kv: kv[1]):
        f = files[0] if files else "?"
        append_event(log, {"file": f, "role": "orchestrator", "event": "lost", "counts": {},
                           "attempt_id": key if not key.startswith("legacy:") else "",
                           "note": "no terminal event — the stage died or was skipped"})


def _append_not_started(log: str, not_started: list) -> None:
    for f in not_started:
        append_event(log, {"file": f, "role": "orchestrator", "event": "not-started",
                           "counts": {},
                           "note": "in the batch but never attempted — not a death"})


def cmd_reconcile(a) -> int:
    """Synthesize `lost` ONLY where no terminal event exists.

    Two distinctions the pre-repair version collapsed, both of which produced
    false alarms — and a log that cries wolf stops being read:

      lost         an attempt STARTED and never reached a terminal event.
      not-started  a file in the batch that was never attempted at all. Not a
                   death; usually the batch was cut short.

    And it no longer infers anything from a gate exit code. A handled gate
    failure is terminal because the workflow APPENDS `gate-failed`, not because
    reconcile guessed from `gate exit=1`.
    """
    attempts = attempts_of(load(a.log))
    expected = [f for f in (a.files.split(",") if a.files else []) if f]
    lost, terminal_files, started_files = _classify(attempts)
    if not expected:
        expected = sorted(started_files)
    not_started = sorted(f for f in expected if f not in started_files)

    _append_lost(a.log, lost)
    _append_not_started(a.log, not_started)

    print(json.dumps({"expected": len(expected), "attempts": len(attempts),
                      "terminal_files": len(terminal_files),
                      "lost": len(lost), "lost_attempts": [k for k, _ in lost],
                      "lost_files": sorted({f for _, fs in lost for f in fs}),
                      "not_started": not_started}, indent=1))
    return 0
