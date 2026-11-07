"""Sequence and identity integrity of the event stream (SEQ-*, EVT-001, SCH-001)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from _reduce_model import problem, schema_problems


@dataclass(frozen=True)
class SequenceFacts:
    problems: list
    last_seq: int | None
    unsequenced: int
    gaps: list


def _gap_problems(seqs: list) -> tuple:
    """(problems, gaps) for duplicate and missing sequence numbers."""
    if not seqs:
        return [], []
    seq_counts = Counter(seqs)
    dupes = sorted(s for s, n in seq_counts.items() if n > 1)
    gaps = [n for n in range(min(seqs), max(seqs) + 1) if n not in seq_counts]
    problems = [problem("SEQ-001", detail=dupes)] if dupes else []
    if gaps:
        problems.append(problem("SEQ-002", detail=gaps,
                                why="a gap in seq proves an event is absent"))
    return problems, gaps


def _seq_problems(rows: list) -> tuple:
    """(problems, seqs, unsequenced event ids, gaps) for the sequence numbers."""
    seqs = [r["seq"] for r in rows if isinstance(r.get("seq"), int)]
    unsequenced = [r.get("event_id", "?") for r in rows if not isinstance(r.get("seq"), int)]
    problems = [problem("SEQ-003", detail=unsequenced)] if unsequenced else []
    gap_problems, gaps = _gap_problems(seqs)
    return problems + gap_problems, seqs, unsequenced, gaps


def _identity_problems(rows: list) -> list:
    eid_counts = Counter(r.get("event_id") for r in rows if r.get("event_id"))
    dup_eids = sorted(e for e, n in eid_counts.items() if n > 1)
    problems = [problem("EVT-001", detail=dup_eids)] if dup_eids else []
    for r in rows:
        problems.extend(schema_problems(r))
    return problems


def order_rows(rows: list) -> None:
    """Order is `seq`, never the clock; ts and event_id only break ties."""
    rows.sort(key=lambda r: (r.get("seq") if isinstance(r.get("seq"), int) else 0,
                             r.get("ts", ""), r.get("event_id", "")))


def sequence_facts(rows: list) -> SequenceFacts:
    problems, seqs, unsequenced, gaps = _seq_problems(rows)
    problems += _identity_problems(rows)
    return SequenceFacts(problems, max(seqs) if seqs else None, len(unsequenced), gaps)
