"""`stats`: the calibration numbers — closure rate, work rate, escalation rate, streaks."""
from __future__ import annotations

import json
from collections import Counter

from _progress_figures import evaluation_figures, rejection_causes, total, zero_work_streaks
from _progress_journal import load


def _scoped(a, rows: list[dict]) -> tuple[list[dict], dict]:
    """Rows filtered to one policy epoch / run. NEVER average across a policy change:
    the campaign-wide escalation_rate after the criterion was replaced still
    counted every escalation made under the superseded rule, so it measured
    neither regime and would have buried the new signal for many ticks."""
    scope = {}
    if getattr(a, "epoch", ""):
        rows = [r for r in rows if r.get("policy_epoch") == a.epoch]
        scope["policy_epoch"] = a.epoch
    if getattr(a, "run", ""):
        rows = [r for r in rows if r.get("run_id") == a.run]
        scope["run_id"] = a.run
    if not scope:
        scope["warning"] = ("unfiltered: spans every policy epoch, so any rate "
                            "below mixes regimes and measures none of them")
    return rows, scope


def cmd_stats(a) -> int:
    rows, scope = _scoped(a, load(a.log))
    ev = evaluation_figures(rows)
    best, streak = zero_work_streaks(rows)
    # The counters that answer "did the rule fixes change behaviour" are
    # CAUSE-SEPARATED: "6 rejected" is a number, "6 rejected for scope" is a
    # diagnosis, and rejection for insufficient evidence and for a wrong fix call
    # for opposite corrections.
    fixes = [r for r in rows if r.get("event") == "fix"]
    reviews = [r for r in rows if r.get("event") == "review"]
    out = {"scope": scope,
           "events": dict(Counter(r.get("event") for r in rows)),
           **{k: ev[k] for k in ("files_evaluated", "files_with_work", "work_rate",
                                 "findings_disposed", "escalated", "escalation_rate")},
           "closes": dict(Counter(r.get("status") for r in rows if r.get("event") == "close")),
           "max_zero_work_streak": best,
           "current_zero_work_streak": streak,
           "work_ordered": ev["work_ordered"],
           "work_applied": total(fixes, "applied"),
           "work_not_applied": total(fixes, "not_applied"),
           "items_rejected": total(reviews, "rejected"),
           "rejected_by_cause": dict(rejection_causes(reviews)),
           "shared_rulings": len({r.get("ruling_id") for r in rows if r.get("ruling_id")}),
           "tests_added": total(fixes, "tests_added"),
           "items_reopened_after_review": total(reviews, "reopened")}
    print(json.dumps(out, indent=1))
    return 0
