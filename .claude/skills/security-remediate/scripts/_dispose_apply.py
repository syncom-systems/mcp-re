"""Applying a validated plan: the ledger rows, then the journal events."""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import ledger
import progress
from _dispose_validate import BLOCKING, TERMINAL

# An escalation is the human's whole brief — question, what was checked, the
# alternatives — so it gets room; every other reason is one line.
REASON_MAX = {"escalated": 800}
REASON_MAX_DEFAULT = 300


@dataclass(frozen=True)
class Run:
    """The identity of one dispose call: where it writes and under which attempt."""
    log: str
    ledger: str
    package: str
    attempt: str
    run: str
    tier: str
    model: str
    epoch: str
    note: str
    dry_run: bool


def _reason(d: dict) -> str:
    """One line, bounded. The package is the full record; the ledger and the
    journal carry the line a reader acts on."""
    r = " ".join(str(d.get("reason") or "").split())
    cap = REASON_MAX.get(d.get("status", ""), REASON_MAX_DEFAULT)
    return r if len(r) <= cap else r[:cap - 1] + "…"


def _note(existing: str, attempt: str, tier: str, reason: str) -> str:
    """Append, never replace: `notes` also carries the owner's rulings, and an
    evaluator's reason overwriting a recorded human decision would erase it."""
    if not reason:
        return existing
    entry = "[%s %s] %s" % (attempt, tier, reason)
    return (existing.rstrip() + "\n" + entry) if existing.strip() else entry


def _apply_disposition(e: dict, d: dict, run: Run) -> None:
    e["status"] = d["status"]
    method = d.get("method") or ("review-adjudicated" if d["status"] == "needs-senior-eval"
                                 else "manual-source")
    e.setdefault("verified", {})["method"] = method
    e["notes"] = _note(str(e.get("notes") or ""), run.attempt, run.tier, _reason(d))
    for source, target in (("duplicate_of", "duplicate_of"), ("premise", "premise"),
                           ("cluster", "cluster_id"), ("ruling", "ruling_id")):
        if d.get(source):
            e[target] = str(d[source])
    if d.get("issue"):
        e.setdefault("refs", {})["issue"] = d["issue"]


def apply_to_ledger(rows: dict, plan: dict, run: Run) -> None:
    for fid, d in plan["disposed"].items():
        _apply_disposition(rows[fid], d, run)
    ledger._save(run.ledger, rows)


def _common(run: Run, path: str) -> dict:
    return dict(log=run.log, file=path, attempt=run.attempt, run=run.run, epoch=run.epoch,
                tier=run.tier, model=run.model)


def _close_event(d: dict, rows: dict, run: Run, common: dict) -> None:
    progress.cmd_close(argparse.Namespace(
        **common, role="evaluator", id=d["id"], status=d["status"],
        severity=str(rows[d["id"]].get("severity", "")), reason=_reason(d),
        duplicate_of=str(d.get("duplicate_of") or ""), cluster=str(d.get("cluster") or ""),
        ruling=str(d.get("ruling") or ""), evidence_ref=run.package))


@dataclass(frozen=True)
class _Journal:
    """What every `evaluate` / terminal event of one dispose call carries."""
    run: Run
    plan: dict
    blocked: list
    common: dict
    counts: dict
    rulings: list
    note: str

    def append(self, event: str) -> None:
        progress.cmd_append(argparse.Namespace(
            **self.common, role="evaluator", event=event,
            counts=",".join("%s=%d" % kv for kv in self.counts.items()), note=self.note,
            work_ids=",".join(self.plan["work_ids"]),
            escalation_ids=",".join(d["id"] for d in self.blocked),
            finding_ids="", ruling=self.rulings[0] if len(self.rulings) == 1 else "",
            reject_causes="", evidence_ref=self.run.package))


def _terminal_event(plan: dict, run: Run) -> str | None:
    return "dry-run" if run.dry_run else "no-code-change" if not plan["work_ids"] else None


def _summary(pkg: dict, plan: dict, journal: _Journal, terminal: str | None) -> dict:
    return {"applied": True, "file": str(pkg.get("file", "")), **journal.counts,
            "delete_or_wire": len(pkg.get("delete_or_wire") or []),
            "terminal_event": terminal or "(worker + reviewer carry it)",
            "escalation_ids": [d["id"] for d in journal.blocked],
            "rulings": journal.rulings,
            "work_ids": plan["work_ids"]}


def write_journal(pkg: dict, rows: dict, plan: dict, run: Run) -> dict:
    """Write the closures and the evaluate/terminal events; the summary to print."""
    closed = [d for d in plan["disposed"].values() if d["status"] in TERMINAL]
    blocked = [d for d in plan["disposed"].values() if d["status"] in BLOCKING]
    common = _common(run, str(pkg.get("file", "")))
    for d in closed:
        _close_event(d, rows, run, common)
    counts = {"work": len(plan["work_ids"]), "closed": len(closed), "escalated": len(blocked),
              "disposed": len(closed) + len(blocked)}
    journal = _Journal(
        run, plan, blocked, common, counts,
        sorted({str(d.get("ruling")) for d in blocked if d.get("ruling")}),
        # The counts are fields already; a note exists only to say what blocks.
        run.note or str(pkg.get("blocked_on") or ""))
    journal.append("evaluate")
    terminal = _terminal_event(plan, run)
    if terminal:
        journal.append(terminal)
    return _summary(pkg, plan, journal, terminal)
