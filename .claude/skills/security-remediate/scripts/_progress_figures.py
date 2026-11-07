"""The tallies `stats` reports: streaks, per-file evaluations, review outcomes."""
from __future__ import annotations

from collections import Counter, defaultdict


def zero_work_streaks(rows: list[dict]) -> tuple[int, int]:
    """(longest, current) run of consecutive evaluated files that produced no work
    item — the loop turning findings into rulings instead of fixes."""
    streak = best = 0
    for r in [r for r in rows if r.get("event") == "evaluate"]:
        streak = streak + 1 if r.get("counts", {}).get("work", 0) == 0 else 0
        best = max(best, streak)
    return best, streak


def total(rows: list[dict], key: str) -> int:
    return sum(r.get("counts", {}).get(key, 0) for r in rows)


def rejection_causes(reviews: list[dict]) -> Counter:
    by_cause: Counter = Counter()
    for r in reviews:
        by_cause.update(r.get("reject_causes") or [])
    return by_cause


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def evaluation_figures(rows: list[dict]) -> dict:
    """What the last `evaluate` event of each file asserted about its dispositions."""
    per_file: dict[str, dict] = defaultdict(dict)
    for r in [r for r in rows if r.get("event") == "evaluate"]:
        per_file[r["file"]] = r.get("counts", {})
    evaluated = list(per_file.values())
    work = sum(1 for c in evaluated if c.get("work", 0) > 0)
    esc = sum(c.get("escalated", 0) for c in evaluated)
    disp = sum(c.get("disposed", 0) for c in evaluated)
    return {"files_evaluated": len(evaluated), "files_with_work": work,
            "work_rate": ratio(work, len(evaluated)),
            "findings_disposed": disp, "escalated": esc,
            "escalation_rate": ratio(esc, disp),
            "work_ordered": sum(c.get("work", 0) for c in evaluated)}
