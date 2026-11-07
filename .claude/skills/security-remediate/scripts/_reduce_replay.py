"""Replay of the ordered events into attempts and finding closures.

`Replay.feed` is the whole state machine: a `close` event settles a finding, any
other event advances an attempt. Problems are collected in the order they are
found, which is the order the report lists them in.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from _reduce_model import (SNAPSHOT_EVENTS, TERMINAL_EVENTS, attempt_key, problem)


@dataclass
class Attempt:
    events: list = field(default_factory=list)
    files: set = field(default_factory=set)
    stages: list = field(default_factory=list)
    terminal: str | None = None
    asserted: dict = field(default_factory=dict)
    role: str = ""
    tier: str = ""
    model: str = ""
    run_ids: list = field(default_factory=list)
    work_ordered: set = field(default_factory=set)
    work_resolved: set = field(default_factory=set)
    escalation_ids: set = field(default_factory=set)
    evidence_ref: str = ""
    superseded_terminals: list = field(default_factory=list)


def _finding_row(fid: str, r: dict) -> dict:
    return {"finding_id": fid, "status": r.get("status", ""),
            "severity": r.get("severity", ""),
            "file": r.get("file", ""),
            "attempt_id": r.get("attempt_id", ""),
            "run_id": r.get("run_id", ""),
            "duplicate_of": r.get("duplicate_of") or "",
            "cluster_id": r.get("cluster_id") or "",
            "ruling_id": r.get("ruling_id") or "",
            "evidence_ref": r.get("evidence_ref") or ""}


def _is_snapshot(r: dict) -> bool:
    if not r.get("counts"):
        return False
    return r.get("counts_kind") == "attempt_snapshot" or r.get("event", "") in SNAPSHOT_EVENTS


class Replay:
    def __init__(self) -> None:
        self.attempts: dict = {}
        self.findings: dict = {}
        self.evidence_refs: dict = {}
        self.problems: list = []

    def feed(self, r: dict) -> None:
        if r.get("evidence_ref"):
            self.evidence_refs.setdefault(r["evidence_ref"], r.get("event_id", "?"))
        if r.get("event", "") == "close":
            self._close(r)
        else:
            self._stage(r)

    def _note_run_id(self, key: str, r: dict) -> None:
        rid = r.get("run_id") or ""
        if rid and rid not in self.attempts[key].run_ids:
            self.attempts[key].run_ids.append(rid)

    def _after_terminal(self, key: str, r: dict) -> None:
        # Only an attempt that already exists can have ended; a close that
        # precedes its attempt's first stage event is legitimate ordering.
        if key in self.attempts and self.attempts[key].terminal:
            self.problems.append(problem(
                "ATT-002", attempt_id=key, seq=r.get("seq"),
                detail="%s after terminal %s" % (r.get("event"), self.attempts[key].terminal)))

    def _close(self, r: dict) -> None:
        fid = r.get("finding_id") or r.get("id")
        if not fid:
            return                   # reported as SCH-001
        if r.get("attempt_id"):
            self._after_terminal(r["attempt_id"], r)
            if r["attempt_id"] in self.attempts:
                self._note_run_id(r["attempt_id"], r)
        self._note_restatus(fid, r)
        self.findings[fid] = _finding_row(fid, r)

    def _note_restatus(self, fid: str, r: dict) -> None:
        prior = self.findings.get(fid)
        if prior and prior["status"] != r.get("status"):
            self.problems.append(problem("FND-001", finding_id=fid,
                                         detail="%s -> %s" % (prior["status"], r.get("status"))))

    def _stage(self, r: dict) -> None:
        ev = r.get("event", "")
        key = attempt_key(r)
        if ev not in TERMINAL_EVENTS:
            self._after_terminal(key, r)
        a = self.attempts.setdefault(key, Attempt())
        self._record_stage(a, key, r)
        self._advance_work(a, key, r)
        # Snapshot counts are ASSERTIONS about the attempt. Keep the latest; never
        # add them together, which is the double-count the old stats invited.
        if _is_snapshot(r):
            a.asserted = dict(r["counts"])
        if ev in TERMINAL_EVENTS:
            self._terminal(a, key, ev)

    def _advance_work(self, a: Attempt, key: str, r: dict) -> None:
        ev = r.get("event", "")
        if ev == "evaluate":
            a.work_ordered |= set(r.get("work_ids") or [])
        elif ev == "review":
            self._review(a, key, r)

    def _record_stage(self, a: Attempt, key: str, r: dict) -> None:
        a.events.append(r.get("event_id", ""))
        if r.get("file"):
            a.files.add(r["file"])
        a.stages.append(r.get("event", ""))
        self._note_run_id(key, r)
        a.role = a.role or r.get("role", "")
        a.tier = a.tier or r.get("tier", "")
        a.model = a.model or r.get("model", "")
        a.escalation_ids |= set(r.get("escalation_ids") or [])
        a.evidence_ref = a.evidence_ref or (r.get("evidence_ref") or "")

    def _review(self, a: Attempt, key: str, r: dict) -> None:
        # A review resolves work in exactly two structural ways: it NAMES the
        # items it accepted, or it names none and asserts zero rejections
        # (accept-all). A partial review that names nothing cannot say which
        # items landed, and the reducer will not read its prose to find out.
        named = set(r.get("work_ids") or [])
        rejected = (r.get("counts") or {}).get("rejected")
        if named:
            self._review_named(a, key, r, named)
        elif rejected == 0:
            a.work_resolved |= a.work_ordered
        else:
            self._review_unnamed(a, key, r, rejected)

    def _review_named(self, a: Attempt, key: str, r: dict, named: set) -> None:
        stray = sorted(named - a.work_ordered)
        if stray:
            self.problems.append(problem("WRK-001", attempt_id=key, seq=r.get("seq"),
                                         detail=stray))
        a.work_resolved |= named & a.work_ordered

    def _review_unnamed(self, a: Attempt, key: str, r: dict, rejected) -> None:
        unresolved = a.work_ordered - a.work_resolved
        if unresolved:
            self.problems.append(problem(
                "WRK-002", attempt_id=key, seq=r.get("seq"), detail=sorted(unresolved),
                why="review rejected=%s but named no work_ids, so which items "
                    "landed is not recorded; they stay unresolved" % rejected))

    def _terminal(self, a: Attempt, key: str, ev: str) -> None:
        prior = a.terminal
        if prior and prior != ev:
            self._second_terminal(a, key, prior, ev)
        a.terminal = ev

    def _second_terminal(self, a: Attempt, key: str, prior: str, ev: str) -> None:
        # An early close that a LATER, more authoritative stage completed is a
        # different fact from two stages contradicting each other, and collapsing
        # them is how a permanent unresolved entry teaches people to ignore the
        # report. `review` is the reviewer's verdict on the finished diff, so it
        # supersedes an earlier close. Observed: three tick-2 attempts were closed
        # `gate-failed` by a worker under a superseded contract, then genuinely
        # reviewed.
        if ev == "review" and prior != "review":
            a.superseded_terminals.append(prior)
            self.problems.append(problem("ATT-004", attempt_id=key,
                                         detail="%s superseded by review" % prior))
        else:
            self.problems.append(problem("ATT-001", attempt_id=key,
                                         detail="%s then %s" % (prior, ev)))


def replay_events(rows: list) -> Replay:
    replay = Replay()
    for r in rows:
        replay.feed(r)
    return replay
