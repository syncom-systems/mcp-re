"""Journal-versus-ledger cross-check (LED-001, LED-002).

The ledger is authoritative for FINDING state, so the blocking set is read from it,
not from journal closures: migrated history predates escalation identities, and
the migration cannot invent what was never recorded, but every one of those
findings IS in the ledger.
"""
from __future__ import annotations

from _reduce_model import problem

_LEDGER_BLOCKING_STATUS = ("escalated", "needs-senior-eval", "exhausted",
                           "architecture-blocked", "regression")


def _blocking_row(fid: str, row: dict) -> dict:
    return {"finding_id": fid, "status": row.get("status", ""),
            "severity": row.get("severity", ""),
            "file": row.get("path") or row.get("file", ""),
            "ruling_id": row.get("ruling_id") or "",
            "cluster_id": row.get("cluster_id") or "",
            "duplicate_of": row.get("duplicate_of") or "",
            "attempt_id": "", "evidence_ref": ""}


def _blocking(ledger: dict) -> list:
    return [_blocking_row(fid, row) for fid, row in sorted(ledger.items())
            if row.get("status") in _LEDGER_BLOCKING_STATUS]


def _compare(findings: dict, ledger: dict) -> tuple:
    disagree, absent = [], []
    for fid, f in sorted(findings.items()):
        row = ledger.get(fid)
        if row is None:
            absent.append(fid)
        elif row.get("status") != f["status"]:
            disagree.append({"finding_id": fid, "journal": f["status"],
                             "ledger": row.get("status")})
    return absent, disagree


def _usable_check(findings: dict, ledger: dict) -> tuple:
    absent, disagree = _compare(findings, ledger)
    check = {"checked": True, "ledger_rows": len(ledger),
             "closures_in_journal": len(findings),
             "absent_from_ledger": absent,
             "status_disagreements": disagree}
    problems = []
    if absent:
        problems.append(problem("LED-001", detail=absent,
                                why="the journal closed a finding the ledger does not hold "
                                    "— the population may have been lost"))
    if disagree:
        problems.append(problem("LED-002", detail=disagree))
    return check, problems


def ledger_cross_check(inp, findings: dict, ledger_path: str) -> tuple:
    """(ledger_check, ledger_blocking, problems) for one input snapshot."""
    if inp.ledger_usable:
        check, problems = _usable_check(findings, inp.ledger)
        return check, _blocking(inp.ledger), problems
    if ledger_path:
        reason = "ledger absent" if inp.ledger_bytes is None else "live snapshot unstable"
        return {"checked": False, "reason": reason}, [], []
    return {"checked": False}, [], []
