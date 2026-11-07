"""The two writing subcommands: `append` (a stage event) and `close` (a disposition)."""
from __future__ import annotations

import uuid

from _progress_journal import SNAPSHOT_EVENTS, append_event


def _counts(spec: str | None) -> dict:
    out: dict[str, int] = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            out[k.strip()] = int(v)
        except ValueError:
            pass
    return out


def _ids(spec: str | None) -> list:
    """Comma-separated identities -> list. Empty stays empty, never [""]."""
    return [x.strip() for x in (spec or "").split(",") if x.strip()]


def _present(**fields) -> dict:
    """The fields that carry a value: an empty one is absent from the record."""
    return {k: v for k, v in fields.items() if v}


def _counts_kind(counts: dict, event: str) -> str:
    # Counts are a checksum over the attempt, not a delta to accumulate.
    if not counts:
        return ""
    return "attempt_snapshot" if event in SNAPSHOT_EVENTS else "stage_delta"


def cmd_append(a) -> int:
    c = _counts(a.counts)
    rec = {"file": a.file, "role": a.role, "event": a.event,
           "tier": a.tier, "model": a.model, "counts": c, "note": (a.note or "")[:400]}
    # The correlation key. File path + arrival order cannot distinguish a retry
    # from the attempt it replaced: `state.py` was evaluated, went `lost`, and
    # on re-dispatch its second attempt would silently overwrite the first in
    # every per-file tally. One attempt = one id, shared by all its events.
    rec["attempt_id"] = a.attempt or ("att-" + uuid.uuid4().hex[:12])
    rec["run_id"] = a.run or ""
    # Which policy regime produced this event. An aggregate rate computed across
    # a rule change measures neither regime: stats are filtered by epoch, never
    # averaged across one.
    # Identities for everything that can remain OUTSTANDING: the journal must say
    # WHICH escalations are awaiting a ruling, not only how many. Rejection
    # reasons are cause-separated for the same reason — a bare `rejected=6` cannot
    # drive any decision. `note` stays bounded and human-readable; the full
    # reasoning lives in the artifact `evidence_ref` points at.
    rec.update(_present(policy_epoch=a.epoch,
                        counts_kind=_counts_kind(c, a.event),
                        work_ids=_ids(a.work_ids),
                        escalation_ids=_ids(a.escalation_ids),
                        finding_ids=_ids(a.finding_ids),
                        ruling_id=a.ruling,
                        reject_causes=_ids(a.reject_causes),
                        evidence_ref=a.evidence_ref))
    append_event(a.log, rec)
    return 0


def cmd_close(a) -> int:
    rec = {"file": a.file, "role": a.role, "event": "close",
           "status": a.status, "id": a.id, "finding_id": a.id, "severity": a.severity,
           "tier": a.tier, "model": a.model, "note": (a.reason or "")[:600]}
    rec["attempt_id"] = a.attempt or ""
    rec["run_id"] = a.run or ""
    # Structural, not prose. "Duplicate of 0907afb94e8f36bf" in a note cannot be
    # reduced to a unique-defect count without an LLM parsing English; as a field
    # it collapses N observations onto one defect deterministically. A shared
    # ruling discharges a whole escalation set at once: 30 escalations collapsing
    # onto ~4 architectural questions is an aggregation problem, not 30
    # independent human decisions.
    rec.update(_present(policy_epoch=a.epoch, duplicate_of=a.duplicate_of,
                        cluster_id=a.cluster, ruling_id=a.ruling,
                        evidence_ref=a.evidence_ref))
    append_event(a.log, rec)
    return 0
