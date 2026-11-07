"""`watch`: read JSONL events on stdin and print ONLY anomalies.

Deliberately dumb and cheap: a filter that runs for days and wakes a model
only on a hit. It NOTIFIES — it must never be able to stop the lane, because
the safety story here rests on there being exactly one writer.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from _progress_render import short


@dataclass
class _Watcher:
    zero_work_streak: int
    close_rate: float
    anchor_misses: int
    zero_streak: int = 0
    reject_streak: int = 0

    def feed(self, r: dict) -> list[str]:
        """The alert lines one event raises, in order."""
        f, ev = short(r.get("file", "")), r.get("event")
        handler = {"evaluate": self._evaluate, "gate": self._gate, "review": self._review,
                   "fix": self._fix}.get(ev)
        if handler:
            return handler(r, f)
        return self._terminal(r, f, ev)

    def _evaluate(self, r: dict, f: str) -> list[str]:
        c = r.get("counts", {}) or {}
        out = []
        if c.get("work", 0) == 0:
            self.zero_streak += 1
            if self.zero_streak >= self.zero_work_streak:
                out.append("ALERT zero-work-streak=%d — the lane is producing rulings, not fixes (last: %s)"
                           % (self.zero_streak, f))
        else:
            self.zero_streak = 0
        disposed = c.get("disposed", 0)
        closed = c.get("closed", 0)
        if disposed and closed / disposed >= self.close_rate:
            out.append("ALERT close-rate %d/%d on %s — an evaluator may be closing too freely"
                       % (closed, disposed, f))
        return out

    def _gate(self, r: dict, f: str) -> list[str]:
        if r.get("counts", {}).get("exit", 0) != 0:
            return ["ALERT gate FAILED on %s — %s" % (f, (r.get("note") or "")[:160])]
        return []

    def _review(self, r: dict, f: str) -> list[str]:
        v = (r.get("note") or "")
        if r.get("counts", {}).get("rejected", 0) or "reject" in v.lower():
            self.reject_streak += 1
            in_a_row = " (%d in a row)" % self.reject_streak if self.reject_streak > 1 else ""
            return ["ALERT review REJECTED on %s%s" % (f, in_a_row)]
        self.reject_streak = 0
        return []

    def _fix(self, r: dict, f: str) -> list[str]:
        c = r.get("counts", {}) or {}
        if c.get("not_applied", 0) >= self.anchor_misses:
            return ["ALERT %d anchors did not match on %s — packets are stale, re-derive rather than retry"
                    % (c["not_applied"], f)]
        return []

    @staticmethod
    def _terminal(r: dict, f: str, ev: str | None) -> list[str]:
        if ev == "lost":
            return ["ALERT no terminal event for %s — a stage died" % f]
        if ev == "close" and r.get("severity") in ("critical", "high"):
            return ["ALERT a %s finding was CLOSED as %s on %s — %s"
                    % (r.get("severity"), r.get("status"), f, (r.get("note") or "")[:160])]
        if ev == "regression":
            return ["ALERT REGRESSION on %s — a fixed finding reappeared" % f]
        return []


def _event(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except ValueError:
        return None


def cmd_watch(a) -> int:
    watcher = _Watcher(a.zero_work_streak, a.close_rate, a.anchor_misses)
    for line in sys.stdin:
        r = _event(line)
        if r is None:
            continue
        for alert in watcher.feed(r):
            print(alert)
        sys.stdout.flush()
    return 0
