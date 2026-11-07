"""Per-attempt truth derived from identities, with the asserted counts CHECKED
against it (RUN-001, ATT-003, CNT-001)."""
from __future__ import annotations

from _reduce_model import BLOCKING_FINDING_STATUS, TERMINAL_FINDING_STATUS, problem


def _derived(findings: dict, key: str) -> tuple:
    mine = [f for f in findings.values() if f["attempt_id"] == key]
    return (sum(1 for f in mine if f["status"] in TERMINAL_FINDING_STATUS),
            sum(1 for f in mine if f["status"] in BLOCKING_FINDING_STATUS))


def _closed_mismatch(asserted: dict, derived_closed: int) -> dict:
    if "closed" not in asserted or asserted["closed"] == derived_closed:
        return {}
    return {"closed": {"asserted": asserted["closed"], "derived": derived_closed}}


def _escalated_mismatch(a) -> dict:
    if not a.escalation_ids or "escalated" not in a.asserted:
        return {}
    if a.asserted["escalated"] == len(a.escalation_ids):
        return {}
    return {"escalated": {"asserted": a.asserted["escalated"],
                          "derived": len(a.escalation_ids)}}


def _count_mismatch(a, derived_closed: int) -> dict:
    """Only what the journal can account for is checked: a `closed` assertion is
    checkable because closures carry identities. `disposed` is NOT checked, because
    the field was applied inconsistently by the agents and checking it would
    manufacture noise, not signal."""
    return {**_closed_mismatch(a.asserted, derived_closed), **_escalated_mismatch(a)}


def _attempt_problems(key: str, a, live: bool, mismatch: dict) -> list:
    out = []
    if len(a.run_ids) > 1:
        out.append(problem("RUN-001", attempt_id=key, detail=a.run_ids))
    if not a.terminal:
        out.append(problem("ATT-003", "info" if live else "", attempt_id=key,
                           detail="no terminal event" + (" yet" if live else "")))
    if mismatch:
        out.append(problem("CNT-001", attempt_id=key, detail=mismatch))
    return out


def _summary(key: str, a, derived: dict, mismatch: dict) -> dict:
    return {
        "attempt_id": key, "files": sorted(a.files),
        "run_id": a.run_ids[0] if a.run_ids else "",
        "role": a.role, "tier": a.tier, "model": a.model,
        "stages": a.stages, "terminal": a.terminal,
        "superseded_terminals": a.superseded_terminals,
        "work_ids": sorted(a.work_ordered),
        "work_resolved": sorted(a.work_resolved),
        "work_unresolved": sorted(a.work_ordered - a.work_resolved),
        "escalation_ids": sorted(a.escalation_ids),
        "evidence_ref": a.evidence_ref,
        "asserted_counts": a.asserted,
        "derived": derived,
        "counts_mismatch": mismatch,
    }


def summarize_attempts(attempts: dict, findings: dict, live: bool) -> tuple:
    """(by_attempt, problems)."""
    by_attempt: dict = {}
    problems: list = []
    for key, a in attempts.items():
        closed, blocking = _derived(findings, key)
        mismatch = _count_mismatch(a, closed)
        problems += _attempt_problems(key, a, live, mismatch)
        by_attempt[key] = _summary(key, a, {"closed": closed, "blocking": blocking}, mismatch)
    return by_attempt, problems
