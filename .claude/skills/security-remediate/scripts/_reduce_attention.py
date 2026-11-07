"""What a human must look at. Built only from identities — never from prose."""
from __future__ import annotations

from collections import defaultdict

from _reduce_model import BLOCKING_FINDING_STATUS, STATE_SCHEMA_VERSION


def _blocking(state: dict) -> dict:
    """Union of what the journal saw and what the ledger holds; the ledger is
    authoritative for finding state, the journal for operation state."""
    blocking = {f["finding_id"]: f for f in state["findings"].values()
                if f["status"] in BLOCKING_FINDING_STATUS}
    for f in state.get("ledger_blocking", []):
        blocking.setdefault(f["finding_id"], f)
    return blocking


def _by_ruling(blocking: dict) -> dict:
    """Escalations grouped by the shared ruling that would discharge them: one
    architectural answer closes a whole set deterministically. UNGROUPED is the
    backlog to cluster — it is a work item, not a resting state."""
    by_ruling: dict = defaultdict(list)
    for f in blocking.values():
        by_ruling[f["ruling_id"] or f["cluster_id"] or "UNGROUPED"].append(f["finding_id"])
    return by_ruling


def _by_severity(blocking: dict) -> dict:
    out: dict = defaultdict(int)
    for f in blocking.values():
        out[f["severity"] or "unknown"] += 1
    return out


def _severe_closures(findings: dict) -> list:
    return sorted(
        (f["finding_id"], f["severity"], f["status"], f["file"])
        for f in findings.values()
        if f["severity"] in ("critical", "high")
        and f["status"] in ("false-positive", "premise", "constraint"))


def attention(state: dict) -> dict:
    att = state["attempts"]
    blocking = _blocking(state)
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "journal_sha256": state["source"]["journal_sha256"],
        "last_complete_seq": state["source"]["last_complete_seq"],
        "VERDICT": state["verdict"],
        "PROBLEM_COUNTS_BY_CLASS": state["problem_counts_by_class"],
        "NONTERMINAL_ATTEMPTS": sorted(k for k, a in att.items() if not a["terminal"]),
        "LOST_ATTEMPTS": sorted(k for k, a in att.items() if a["terminal"] == "lost"),
        "GATE_FAILED_ATTEMPTS": sorted(k for k, a in att.items()
                                       if a["terminal"] == "gate-failed"),
        "UNRESOLVED_WORK": sorted({w for a in att.values() for w in a["work_unresolved"]}),
        "UNRESOLVED_ESCALATIONS_TOTAL": len(blocking),
        "UNRESOLVED_ESCALATIONS_BY_SEVERITY": dict(sorted(_by_severity(blocking).items())),
        "UNRESOLVED_ESCALATIONS_BY_RULING": {k: sorted(v) for k, v
                                             in sorted(_by_ruling(blocking).items())},
        "SEVERE_CLOSURES_TO_REVIEW": [list(x) for x in _severe_closures(state["findings"])],
        "SEQUENCE_GAPS": state["sequence_gaps"],
        "INTEGRITY_PROBLEMS": state["problems"],
    }
