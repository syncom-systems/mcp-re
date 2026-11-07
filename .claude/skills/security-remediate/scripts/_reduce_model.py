"""Vocabulary of the reducer: schema constants, problem codes and the record check.

`INVARIANTS` is the one table of problem codes. Every problem the reducer reports
is built by `problem`, so a code that is not in the table cannot be emitted.
"""
from __future__ import annotations

import os

AUDITOR_VERSION = "2.0.0"
STATE_SCHEMA_VERSION = 2
# The only journal schema this reducer knows how to validate. An event declaring
# anything else is reported, not guessed at.
JOURNAL_SCHEMA_VERSIONS = {1}

# `evidence_ref` paths are repository-relative. They resolve against ONE root,
# never the working directory, so the answer does not depend on where the
# auditor was launched: this file is <root>/<dot-claude>/skills/<skill>/scripts.
DEFAULT_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))))))

TERMINAL_EVENTS = {"review", "no-code-change", "gate-failed", "exhausted", "lost",
                   "dry-run", "not-started"}
SNAPSHOT_EVENTS = {"evaluate", "no-code-change", "dry-run", "gate-failed", "exhausted"}
STAGE_EVENTS = {"evaluate", "fix", "gate", "regression"}
KNOWN_EVENTS = TERMINAL_EVENTS | STAGE_EVENTS | {"close"}
# Synthesized by `progress.py reconcile`, which writes no run_id and (for a file
# never attempted) no attempt_id. Requiring those fields of them would report the
# harness's own bookkeeping as a protocol breach.
ORCHESTRATOR_SYNTHESIZED = {"lost", "not-started"}
# A closure is terminal for a FINDING. `escalated` and `needs-senior-eval` are
# explicitly NOT here: they block, which is the whole reason they must be
# enumerable rather than merely countable.
TERMINAL_FINDING_STATUS = {"fixed", "false-positive", "premise", "constraint", "duplicate",
                           "superseded", "deleted-with-owner",
                           "positive-control", "informational", "parked-external"}
BLOCKING_FINDING_STATUS = {"escalated", "needs-senior-eval", "exhausted",
                           "architecture-blocked", "open", "regression"}

# code -> (class, kind). `kind` is the name the problem had before codes existed;
# it is kept so every earlier reader and test still means the same thing.
INVARIANTS = {
    "JNL-002": ("warning", "incomplete-final-record"),
    "SEQ-001": ("fatal", "duplicate-seq"),
    "SEQ-002": ("fatal", "missing-events"),
    "SEQ-003": ("error", "unsequenced-event"),
    "EVT-001": ("fatal", "duplicate-event-id"),
    "SCH-001": ("error", "schema-violation"),
    "RUN-001": ("error", "attempt-run-id-changed"),
    "ATT-001": ("fatal", "multiple-terminal-events"),
    "ATT-002": ("error", "event-after-terminal"),
    "ATT-003": ("warning", "nonterminal-attempt"),
    "ATT-004": ("info", "terminal-superseded"),
    "FND-001": ("error", "finding-restatus"),
    "FND-002": ("error", "dangling-duplicate-of"),
    "FND-003": ("error", "duplicate-of-cycle"),
    "CNT-001": ("error", "counts-assertion-mismatch"),
    "WRK-001": ("error", "review-names-unordered-work"),
    "WRK-002": ("warning", "partial-review-without-work-identities"),
    "LED-001": ("error", "closure-absent-from-ledger"),
    "LED-002": ("error", "ledger-journal-status-disagreement"),
    "LED-900": ("warning", "live-snapshot-unstable"),
    "EVD-001": ("warning", "evidence-ref-unresolved"),
}
CLASS_ORDER = ("fatal", "error", "warning", "info")
FAILING_CLASSES = {"fatal", "error"}


def problem(code: str, cls: str = "", **fields) -> dict:
    default_cls, kind = INVARIANTS[code]
    p = {"code": code, "class": cls or default_cls, "kind": kind}
    p.update(fields)
    return p


def attempt_key(rec: dict) -> str:
    return rec.get("attempt_id") or ("legacy:" + rec.get("file", ""))


def _close_missing(r: dict, detail: dict) -> list:
    missing = [k for k in ("status",) if not r.get(k)]
    if not (r.get("finding_id") or r.get("id")):
        missing.append("finding_id")
    if r.get("status") and r["status"] not in TERMINAL_FINDING_STATUS | BLOCKING_FINDING_STATUS:
        detail["unknown_status"] = r["status"]
    return missing


def _envelope_detail(r: dict) -> dict:
    detail: dict = {}
    if r.get("schema_version") and r["schema_version"] not in JOURNAL_SCHEMA_VERSIONS:
        detail["schema_version"] = r["schema_version"]
    ev = r.get("event", "")
    if ev and ev not in KNOWN_EVENTS:
        detail["unknown_event"] = ev
    return detail


def _event_missing(r: dict, detail: dict) -> list:
    ev = r.get("event", "")
    if ev == "close":
        return _close_missing(r, detail)
    if ev in KNOWN_EVENTS and ev not in ORCHESTRATOR_SYNTHESIZED:
        return [k for k in ("attempt_id", "run_id", "file", "role") if not r.get(k)]
    return []


def schema_problems(r: dict) -> list:
    """Required fields per event type. Presence only — the reducer checks VALUES
    through the invariants that consume them."""
    missing = [k for k in ("schema_version", "event_id", "ts", "event") if not r.get(k)]
    detail = _envelope_detail(r)
    missing += _event_missing(r, detail)
    if missing:
        detail["missing"] = sorted(set(missing))
    if not detail:
        return []
    return [problem("SCH-001", event_id=r.get("event_id", "?"), seq=r.get("seq"),
                    detail=detail)]
