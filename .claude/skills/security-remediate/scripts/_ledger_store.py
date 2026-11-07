"""Reading and atomically storing the ledger file."""
from __future__ import annotations

import json
import os

from _persist import atomic_write_lines


def _load(path):
    if not os.path.exists(path):
        return {}
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            out[e["id"]] = e
    return out


def _save(path, by_id):
    """Atomically store the ledger. MUST be called inside `exclusive(path)`.

    The write itself is atomic (temp file + rename), so no reader can observe a
    partial ledger. That is necessary and NOT sufficient: the caller must also
    hold the lock across its own `_load()`, or two writers each store their own
    delta over the same base snapshot and the loser's change is silently lost.
    See `_persist` for the incident this pair of rules was written against.
    """
    # Stable order: by file then id, so diffs are readable.
    rows = sorted(by_id.values(), key=lambda e: (e.get("file", ""), e["id"]))
    atomic_write_lines(path, [json.dumps(e, sort_keys=True) for e in rows])
