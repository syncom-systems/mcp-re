"""The small subcommands: `fingerprint`, `set`, `stats`, `check`."""
from __future__ import annotations

import json
import sys

from _ledger_identity import fingerprint
from _ledger_store import _load, _save
from _ledger_taxonomy import closure_problem, is_open, registered_assumptions
from _persist import exclusive

# Argument name -> the ledger path it is assigned to. A duplicate/cluster relationship
# is a FIELD, not a sentence in `notes`: `status=duplicate` with the twin named only
# in prose cannot be reduced to a unique-defect count without an LLM reading English.
_SET_FIELDS = (("status", ("status",)), ("premise", ("premise",)),
               ("owner_ruling", ("owner_ruling",)), ("note", ("notes",)),
               ("duplicate_of", ("duplicate_of",)), ("cluster", ("cluster_id",)),
               ("ruling", ("ruling_id",)), ("method", ("verified", "method")),
               ("issue", ("refs", "issue")), ("pr", ("refs", "pr")))


def cmd_fingerprint(a):
    print(fingerprint(a.file, a.title))


def _assign(e: dict, path: tuple, value) -> None:
    target = e
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value


def _apply_set(e: dict, a) -> None:
    for arg, path in _SET_FIELDS:
        value = getattr(a, arg)
        if value:
            _assign(e, path, value)


def cmd_set(a):
    # The lock spans load -> mutate -> store. Narrowing it to the store alone
    # reintroduces lost-update: that is the defect that cost 365 findings.
    with exclusive(a.ledger):
        by_id = _load(a.ledger)
        e = by_id.get(a.id)
        if e is None:
            sys.exit(f"set: id {a.id} not in ledger")
        _apply_set(e, a)
        problem = closure_problem(e, registered_assumptions(a.assumptions))
        if problem:
            sys.exit(f"set {a.id}: refused — {problem}")
        _save(a.ledger, by_id)
    print(f"set {a.id}: status={e['status']} refs={e.get('refs')}")


def _tally(rows: list, key: str) -> dict:
    out: dict = {}
    for e in rows:
        out[e[key]] = out.get(e[key], 0) + 1
    return out


def cmd_stats(a):
    by_id = _load(a.ledger)
    assumptions = registered_assumptions(a.assumptions)
    rows = list(by_id.values())
    open_by_sev = _tally([e for e in rows if is_open(e, assumptions)], "severity")
    invalid = sorted(e["id"] for e in rows if closure_problem(e, assumptions))
    print(json.dumps({"total": len(by_id), "by_status": _tally(rows, "status"),
                      "by_severity": _tally(rows, "severity"), "open": sum(open_by_sev.values()),
                      "open_by_severity": open_by_sev,
                      "not_validly_closed": invalid}, indent=1))


def cmd_check(a):
    by_id = _load(a.ledger)
    if not by_id:
        sys.exit(f"check: {a.ledger} holds no findings — an empty ledger checks nothing")
    assumptions = registered_assumptions(a.assumptions)
    problems = [(i, p) for i, e in sorted(by_id.items())
                if (p := closure_problem(e, assumptions))]
    for i, p in problems:
        print(f"  - {i}: {p}")
    if problems:
        print(f"ledger check: FAIL — {len(problems)} of {len(by_id)} row(s) carry no valid disposition")
        return 1
    n_open = sum(1 for e in by_id.values() if is_open(e, assumptions))
    print(f"ledger check: OK — {len(by_id)} row(s), {n_open} open")
    return 0
