"""Package validation: every refusal reason at once, plus the plan the apply step runs."""
from __future__ import annotations

from dataclasses import dataclass

import ledger
from file_findings import ACTIONABLE

TERMINAL = {"false-positive", "premise", "superseded", "duplicate"}
BLOCKING = {"escalated", "needs-senior-eval"}
# Where a reason is read by another actor. Everywhere else it is output tokens
# nobody consumes.
REASONED = {"escalated", "needs-senior-eval", "false-positive", "premise"}
# The can't-close rule, enforced where it is cheapest to enforce: a cheap tier may
# act but not retire a finding behind an authoritative-sounding reason.
CLOSES = {"false-positive", "premise"}


@dataclass(frozen=True)
class _Scope:
    """The ledger as it bears on one file's package."""
    rows: dict
    on_file: dict
    actionable: set
    tier: str


def _covered(item: dict, actionable: set) -> list:
    """The finding ids a work item discharges."""
    ids = [str(x) for x in (item.get("finding_ids") or [])]
    wid = str(item.get("id", ""))
    if wid in actionable and wid not in ids:
        ids.insert(0, wid)
    return ids


@dataclass(frozen=True)
class _Item:
    """One `disposed[]` entry: the package's record, its id and its lowered status."""
    d: dict
    fid: str
    st: str

    @property
    def where(self) -> str:
        return "disposed[%s]" % self.fid


def _status_errors(item: _Item) -> list[str]:
    if item.st in ledger.REFUSED_STATUSES:
        return ["%s: %r is not a disposition — order the fix as work, show it is not a "
                "defect, or escalate it" % (item.where, item.st)]
    if item.st not in TERMINAL | BLOCKING:
        return ["%s: status %r is not one of %s" % (item.where, item.st, sorted(TERMINAL | BLOCKING))]
    return []


def _premise_errors(item: _Item) -> list[str]:
    if item.st != "premise":
        return []
    problem = ledger.closure_problem({"status": item.st, "premise": item.d.get("premise")},
                                     ledger.registered_assumptions())
    return ["%s: %s" % (item.where, problem)] if problem else []


def _reason_errors(item: _Item) -> list[str]:
    if item.st in REASONED and not str(item.d.get("reason", "")).strip():
        return ["%s: %s needs a one-line `reason` — someone acts on it" % (item.where, item.st)]
    return []


def _names_another_ledger_id(twin: str, fid: str, rows: dict) -> bool:
    return bool(twin) and twin != fid and twin in rows


def _duplicate_errors(item: _Item, rows: dict) -> list[str]:
    if item.st != "duplicate":
        return []
    if _names_another_ledger_id(str(item.d.get("duplicate_of", "")), item.fid, rows):
        return []
    return ["%s: `duplicate` needs `duplicate_of` naming ANOTHER ledger id" % item.where]


def _tier_errors(item: _Item, tier: str) -> list[str]:
    if tier == "cheap" and item.st in CLOSES:
        return ["%s: the cheap tier may not close as %s — set `needs-senior-eval` with "
                "the reasoning instead" % (item.where, item.st)]
    if tier == "senior" and item.st == "needs-senior-eval":
        return ["%s: you ARE the senior tier — decide it" % item.where]
    return []


def _disposition_errors(item: _Item, scope: _Scope, seen: dict) -> list[str]:
    errs = ["%s: listed twice" % item.where] if item.fid in seen else []
    if item.fid not in scope.actionable:
        errs.append("%s: not an actionable finding on this file (ledger status: %s)"
                    % (item.where, scope.on_file.get(item.fid, {}).get("status", "NOT ON THIS FILE")))
    return (errs + _status_errors(item) + _premise_errors(item) + _reason_errors(item)
            + _duplicate_errors(item, scope.rows) + _tier_errors(item, scope.tier))


def _disposed(pkg: dict, scope: _Scope, errs: list[str]) -> dict:
    disposed: dict = {}
    for d in pkg.get("disposed") or []:
        fid, st = str(d.get("id", "")), str(d.get("status", "")).lower()
        errs += _disposition_errors(_Item(d, fid, st), scope, disposed)
        disposed[fid] = dict(d, id=fid, status=st)
    return disposed


def _work_item_errors(w: dict, cov: list, actionable: set, disposed: dict) -> list[str]:
    where = "work[%s]" % str(w.get("id", ""))
    errs = []
    if not cov:
        errs.append("%s: discharges no finding — use a finding id as `id`, or list them "
                    "in `finding_ids`" % where)
    for fid in cov:
        if fid not in actionable:
            errs.append("%s: finding %s is not actionable on this file" % (where, fid))
        if fid in disposed:
            errs.append("%s: finding %s is ALSO disposed — one or the other" % (where, fid))
    errs += ["%s: no `%s` — the worker cannot execute it" % (where, k)
             for k in ("anchor", "change", "accept") if not str(w.get(k, "")).strip()]
    return errs


def _work(pkg: dict, actionable: set, disposed: dict, errs: list[str]) -> tuple[list, dict]:
    work_ids: list[str] = []
    by_work: dict = {}
    for w in pkg.get("work") or []:
        wid = str(w.get("id", ""))
        cov = _covered(w, actionable)
        errs += _work_item_errors(w, cov, actionable, disposed)
        for fid in cov:
            by_work.setdefault(fid, wid)
        work_ids.append(wid)
    if len(set(work_ids)) != len(work_ids):
        errs.append("work ids are not unique: %s" % work_ids)
    return work_ids, by_work


def _wire_errors(pkg: dict, disposed: dict, by_work: dict) -> list[str]:
    ids = [str(d.get("id", "")) for d in pkg.get("delete_or_wire") or []]
    return ["delete_or_wire[%s]: must ALSO be disposed or ordered as work" % fid
            for fid in ids if fid not in disposed and fid not in by_work]


def _missing_errors(scope: _Scope, disposed: dict, by_work: dict) -> list[str]:
    missing = sorted(scope.actionable - set(disposed) - set(by_work))
    return ["MISSING %s [%s] %s — every actionable finding needs a disposition or a "
            "work item" % (fid, scope.on_file[fid].get("severity"), scope.on_file[fid].get("title"))
            for fid in missing]


def validate(pkg: dict, rows: dict, path: str, tier: str) -> tuple[list, dict]:
    """Every refusal reason at once, so one retry fixes them all — plus the plan."""
    errs: list[str] = []
    on_file = {i: r for i, r in rows.items() if (r.get("path") or r.get("file")) == path}
    actionable = {i for i, r in on_file.items() if str(r.get("status", "")).lower() in ACTIONABLE}
    scope = _Scope(rows, on_file, actionable, tier)
    disposed = _disposed(pkg, scope, errs)
    work_ids, by_work = _work(pkg, actionable, disposed, errs)
    errs += _wire_errors(pkg, disposed, by_work) + _missing_errors(scope, disposed, by_work)
    plan = {"disposed": disposed, "work_ids": work_ids, "covered": by_work,
            "actionable": sorted(actionable)}
    return errs, plan
