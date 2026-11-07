"""Assembly of the derived state document from the facts the checks produced."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from _reduce_model import (AUDITOR_VERSION, CLASS_ORDER, DEFAULT_REPO_ROOT, FAILING_CLASSES,
                           STATE_SCHEMA_VERSION)


@dataclass(frozen=True)
class Facts:
    """Everything one reduction established; `build_state` only arranges it."""
    inp: object
    seq: object
    by_attempt: dict
    findings: dict
    provenance: object
    unresolved_evidence: list
    ledger_check: dict
    ledger_blocking: list
    problems: list
    ledger_path: str
    repo_root: str
    live: bool


def _sha(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _source(f: Facts) -> dict:
    """Provenance: every value describes the exact bytes that were reduced,
    computed from the snapshot in hand and never re-read. Nothing here may be a
    clock or a random value, or two replays stop being byte-identical."""
    inp = f.inp
    return {
        "auditor_version": AUDITOR_VERSION,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "journal": inp.journal_path,
        "journal_sha256": hashlib.sha256(inp.reduced_bytes).hexdigest(),
        "journal_bytes_reduced": len(inp.reduced_bytes),
        "journal_bytes_dropped_incomplete": inp.dropped_tail,
        "events_reduced": len(inp.rows),
        "last_complete_seq": f.seq.last_seq,
        "ledger": f.ledger_path or None,
        "ledger_sha256": _sha(inp.ledger_bytes),
        "ledger_rows": len(inp.ledger) if inp.ledger is not None else None,
        "live": f.live,
        "snapshot_stable": inp.stable,
        "repo_root_for_evidence": ("<default>" if f.repo_root == DEFAULT_REPO_ROOT
                                   else f.repo_root),
    }


def _totals(f: Facts) -> dict:
    attempts = f.by_attempt.values()
    return {
        "attempts": len(f.by_attempt),
        "attempts_terminal": sum(1 for a in attempts if a["terminal"]),
        "files_touched": len(sorted({file for a in attempts for file in a["files"]})),
        "finding_observations": len(f.findings),
        "unique_defect_clusters": f.provenance.unique_defects,
        "duplicate_observations": f.provenance.duplicates,
    }


def build_state(f: Facts) -> dict:
    counts_by_class = {c: sum(1 for p in f.problems if p["class"] == c) for c in CLASS_ORDER}
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "source": _source(f),
        "events": len(f.inp.rows),
        "unsequenced_events": f.seq.unsequenced,
        "sequence_gaps": f.seq.gaps,
        "attempts": {k: f.by_attempt[k] for k in sorted(f.by_attempt)},
        "findings": {k: f.findings[k] for k in sorted(f.findings)},
        "clusters": {k: sorted(v) for k, v in sorted(f.provenance.clusters.items())},
        "totals": _totals(f),
        "ledger_check": f.ledger_check,
        "ledger_blocking": f.ledger_blocking,
        "unresolved_evidence_refs": f.unresolved_evidence,
        "problem_counts_by_class": counts_by_class,
        "verdict": "fail" if any(counts_by_class[c] for c in FAILING_CLASSES) else "pass",
        "problems": f.problems,
    }
