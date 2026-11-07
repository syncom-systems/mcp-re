"""The append-only journal: sequence numbers, the event envelope, the reader."""
from __future__ import annotations

import json
import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from _persist import append_line, exclusive

SCHEMA_VERSION = 1

# An attempt ends in EXACTLY ONE of these. `gate-failed` was already listed here
# before the repair, but nothing ever APPENDED it — the workflow only returned it
# as a verdict — so a handled gate failure left the attempt looking abandoned and
# reconcile synthesized a false `lost`. A terminal event must be written, never
# inferred from the absence or the exit code of some other event.
TERMINAL_EVENTS = {"review", "no-code-change", "gate-failed", "exhausted", "lost",
                   "dry-run", "not-started"}

# Events whose `counts` are a SNAPSHOT of the attempt's disposition tally, not a
# delta. `evaluate` and the terminal event repeat the same numbers, so anything
# that sums them double-counts. The reducer treats these as assertions to CHECK
# against the identities it replayed, never as state to accumulate.
SNAPSHOT_EVENTS = {"evaluate", "no-code-change", "dry-run", "gate-failed", "exhausted"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_seq(log: str) -> int:
    """Monotonic sequence number from an O(1) sidecar counter.

    A gap in `seq` (…18429, 18430, 18432…) proves an event is missing, which
    file order alone cannot show. The counter is a tiny separate file read and
    bumped inside the lock — deliberately NOT derived by scanning the journal for
    its max, which would be O(n) per append and, worse, would reintroduce the
    read-whole-file/rewrite pattern that destroyed 365 ledger rows.
    """
    counter = log + ".seq"
    try:
        with open(counter, encoding="utf-8") as fh:
            n = int(fh.read().strip() or "0")
    except (OSError, ValueError):
        n = 0
    n += 1
    tmp = counter + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(str(n))
        fh.flush()
        os.fsync(fh.fileno())
    os.rename(tmp, counter)
    return n


def _envelope(rec: dict) -> dict:
    """Stamp the identity fields every event carries, whatever its type."""
    rec.setdefault("schema_version", SCHEMA_VERSION)
    rec.setdefault("event_id", "evt-" + uuid.uuid4().hex[:16])
    rec.setdefault("ts", _now())
    return rec


def append_event(log: str, rec: dict) -> None:
    """Append one event under the lock, so `seq` and the record stay in step.

    The journal write itself is O_APPEND and would be safe unlocked; the lock is
    here only because `seq` must be handed out exactly once. Scope it to the
    counter bump plus the append and nothing else — a lock held across an
    agent's real work is how a lane deadlocks.
    """
    rec = _envelope(rec)
    with exclusive(log + ".jsonl"):
        rec["seq"] = _next_seq(log)
        append_line(log + ".jsonl", json.dumps(rec, sort_keys=True))


def _parse(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except ValueError:
        return None


def load(log: str) -> list[dict]:
    p = log + ".jsonl"
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as fh:
        rows = [_parse(line) for line in fh]
    return [r for r in rows if r is not None]


def attempts_of(rows: list) -> dict:
    """Group events into attempts. Legacy rows without `attempt_id` fall back to
    the file path, which is exactly the ambiguity `attempt_id` was added to end —
    so the fallback is for reading old history, never for writing new."""
    out: dict = defaultdict(list)
    for r in rows:
        key = r.get("attempt_id") or ("legacy:" + r.get("file", ""))
        out[key].append(r)
    return out
