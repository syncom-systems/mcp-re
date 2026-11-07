"""`ingest` (add or refresh rows from a prerun) and `reconcile` (classify a prerun against the ledger)."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from _ledger_identity import _file_of, _findings_of, _location_of, fingerprint
from _ledger_store import _load, _save
from _ledger_taxonomy import OPEN_STATUSES, SUPPRESS
from _persist import exclusive


@dataclass(frozen=True)
class _Entry:
    """The identity, disposition and round an ingested finding is recorded under."""
    fid: str
    status: str
    method: str
    round: str


def _entry_for(f: dict, a) -> _Entry:
    sev = (f.get("severity") or "").lower()
    # critical→low enter the worklist as `open` (all must be dealt with).
    # info is captured off-worklist as `informational` (per-run digest issue).
    status = a.status or ("informational" if sev == "info" else "open")
    method = a.method or ("catalog-logged" if status == "informational" else "review-adjudicated")
    return _Entry(fingerprint(_file_of(f), f.get("title")), status, method, a.round)


def _refresh(e: dict, f: dict, rnd: str) -> None:
    e["last_seen"] = rnd
    loc = _location_of(f)
    if loc:
        e["path"] = loc
    if f.get("line") is not None:
        e["line"] = f.get("line")
    e.setdefault("rounds", [])
    if rnd not in e["rounds"]:
        e["rounds"].append(rnd)


def _new_row(f: dict, entry: _Entry) -> dict:
    return {
        "id": entry.fid,
        "file": _file_of(f),
        # Full repo-relative path and line: the basename alone is not
        # actionable for a fixer, and next_file.py keys the worklist on
        # `path` when present.
        "path": _location_of(f),
        "line": f.get("line"),
        "category": f.get("category", ""),
        "severity": (f.get("severity") or "").lower(),
        "title": f.get("title", ""),
        "status": entry.status,
        "verified": {"method": entry.method, "round": entry.round},
        "refs": {},
        "first_seen": entry.round,
        "last_seen": entry.round,
        "rounds": [entry.round],
        "notes": "",
    }


def cmd_ingest(a):
    if a.status and a.status not in OPEN_STATUSES | {"informational"}:
        sys.exit(f"ingest: --status {a.status!r} refused — a new finding enters open or "
                 f"informational; a disposition is a `set` that names its evidence")
    prerun = json.load(open(a.prerun))
    findings = _findings_of(prerun)
    # Same rule as cmd_set: the lock covers load -> mutate -> store. Ingest is
    # also the RECOVERY path (deterministic fingerprints re-add lost rows and
    # leave existing dispositions untouched), so it must not itself race.
    with exclusive(a.ledger):
        by_id = _load(a.ledger)
        added = updated = 0
        for f in findings:
            entry = _entry_for(f, a)
            if entry.fid in by_id:
                _refresh(by_id[entry.fid], f, a.round)
                updated += 1
            else:
                by_id[entry.fid] = _new_row(f, entry)
                added += 1
        _save(a.ledger, by_id)
    print(f"ingest: +{added} new, {updated} updated -> {a.ledger} "
          f"({len(by_id)} total)")


def _count_by(rows, key):
    out = {}
    for r in rows:
        out[r.get(key, "?")] = out.get(r.get(key, "?"), 0) + 1
    return out


def _unmatched(rec: dict, f: dict, by_file: dict) -> tuple[str, dict]:
    """A finding the ledger has never seen: new, or a fuzzy candidate recurrence
    (same file + same category) that a human or LLM must confirm."""
    cands = [x for x in by_file.get(rec["file"], [])
             if x.get("category") and x["category"] == f.get("category")]
    if not cands:
        return "new", rec
    rec["candidates"] = [{"id": c["id"], "status": c["status"], "title": c["title"]}
                         for c in cands]
    return "candidates", rec


def _bucket(f: dict, by_id: dict, by_file: dict) -> tuple[str, dict]:
    """Which bucket one prerun finding falls in, and its record."""
    fid = fingerprint(_file_of(f), f.get("title"))
    e = by_id.get(fid)
    rec = {"file": _file_of(f), "title": f.get("title", ""),
           "severity": (f.get("severity") or "").lower(), "id": fid}
    if e is None:
        return _unmatched(rec, f, by_file)
    if e["status"] == "fixed":
        rec["was"] = e["refs"]
        return "regression", rec
    rec["status"] = e["status"]
    if e["status"] in SUPPRESS:
        return "suppressed", rec
    # open / escalated / handled-prior-round / duplicate
    rec["refs"] = e.get("refs", {})
    return "tracked", rec


def cmd_reconcile(a):
    by_id = _load(a.ledger)
    by_file = {}
    for e in by_id.values():
        by_file.setdefault(e["file"], []).append(e)
    findings = _findings_of(json.load(open(a.prerun)))
    buckets = {k: [] for k in ("new", "tracked", "regression", "suppressed", "candidates")}
    for f in findings:
        name, rec = _bucket(f, by_id, by_file)
        buckets[name].append(rec)
    out = {
        "summary": {
            "new": len(buckets["new"]), "tracked": len(buckets["tracked"]),
            "regression": len(buckets["regression"]), "suppressed": len(buckets["suppressed"]),
            "fuzzy_candidates": len(buckets["candidates"]),
        },
        "new": buckets["new"], "regression": buckets["regression"],
        "fuzzy_candidates": buckets["candidates"], "tracked": buckets["tracked"],
        "suppressed_count_by_status": _count_by(buckets["suppressed"], "status"),
    }
    print(json.dumps(out, indent=1))
