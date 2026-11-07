"""dispose.py — apply an evaluator's whole package to the ledger and the journal, in ONE call.

(Invoked as `python3 dispose.py …`; no shebang — see reduce.py for why.)

WHY: on a lane run the evaluators spent ~155 of 848 Bash calls on bookkeeping —
one `ledger.py set` per disposition, one `progress.py close` per closure, the
`evaluate` event, the terminal event — and more on re-reading `ledger.py --help`
and the journal to rediscover the protocol. Every one of those turns re-sent the
agent's whole context. The package already holds every decision; this reads it
and writes all of them.

It also moves two checks from prose into code:

  * COMPLETENESS. Every actionable finding on the file must reach exactly one of
    `disposed[]` or a `work[]` item. A package that leaves a finding out is
    REFUSED and nothing is written — a partial apply would let the ledger's
    "every finding reaches a terminal disposition" rule depend on trusting the
    agent's arithmetic.
  * COUNTS. `work / disposed / closed / escalated` are computed from the
    identities, never typed by the agent. Tick 1 had four evaluators counting
    duplicates one way and four the other; tick 2 had `closed=0` beside four
    duplicate closures. A number derived from the record cannot disagree with it.

Package contract (the evaluator writes this, then runs this script once):
  disposed[]  {id, status, [reason], [duplicate_of], [premise], [cluster], [ruling], [issue], [method]}
              status: false-positive | premise | superseded | duplicate
                      (terminal) or escalated | needs-senior-eval (blocking)
              `reason` — one line — is required ONLY where someone acts on it:
              escalated / needs-senior-eval (a question for the human or the
              senior tier) and false-positive / premise (irreversible; the
              only trace if the call was wrong). A duplicate says it with
              `duplicate_of`; a premise names its registered ASM in `premise`;
              superseded needs nothing. A real defect is never closed here: it
              is ordered as work, or escalated.
              `accepted-risk` / `wontfix` are refused: they are not dispositions.
  work[]      {id, anchor, change, accept, standard, [finding_ids]}
              `id` is a finding id, or a work id with `finding_ids` naming the
              findings it discharges
  delete_or_wire[]  informational; each id must ALSO be in disposed[] or work[]

Nothing is written unless everything validates. Exit 0 applied, 2 refused.

Usage:
  dispose.py --ledger <ledger.jsonl> --log <progress> --package <pkg.json> \\
             --attempt <attempt_id> --run <run_id> --tier senior|cheap --model <m> \\
             [--epoch <policy_epoch>] [--dry-run] [--note "<one line>"]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402
from _dispose_apply import Run, apply_to_ledger, write_journal  # noqa: E402
from _dispose_validate import validate  # noqa: E402
from _persist import exclusive, read_jsonl  # noqa: E402


def _arguments() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--log", required=True, help="progress log base path (no extension)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--file", default="", help="expected package.file; refused on mismatch")
    ap.add_argument("--attempt", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--tier", required=True, choices=["senior", "cheap"])
    ap.add_argument("--model", default="")
    ap.add_argument("--epoch", default="")
    ap.add_argument("--dry-run", action="store_true",
                    help="the lane is evaluate-only: write `dry-run` as the terminal event")
    ap.add_argument("--note", default="", help="one line for the evaluate event")
    return ap.parse_args()


def _already_applied(a: argparse.Namespace) -> bool:
    """Idempotency: a second run for the same attempt would double every event."""
    if not os.path.exists(a.log + ".jsonl"):
        return False
    return any(r.get("attempt_id") == a.attempt and r.get("event") == "evaluate"
               for r in read_jsonl(a.log + ".jsonl"))


def _refusal(a: argparse.Namespace, pkg: dict) -> str | None:
    path = str(pkg.get("file", ""))
    if a.file and a.file != path:
        return "REFUSED: package.file is %r, not %r; NOTHING was written." % (path, a.file)
    if _already_applied(a):
        return ("REFUSED: attempt %s already has an `evaluate` event — this package was "
                "applied. Use a new attempt id for a re-evaluation." % a.attempt)
    return None


def main() -> int:
    a = _arguments()
    try:
        pkg = json.load(open(a.package, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("REFUSED: cannot read package %s: %s" % (a.package, e))
        return 2
    refusal = _refusal(a, pkg)
    if refusal:
        print(refusal)
        return 2
    run = Run(log=a.log, ledger=a.ledger, package=a.package, attempt=a.attempt, run=a.run,
              tier=a.tier, model=a.model, epoch=a.epoch, note=a.note, dry_run=a.dry_run)

    with exclusive(a.ledger):
        rows = ledger._load(a.ledger)
        errs, plan = validate(pkg, rows, str(pkg.get("file", "")), a.tier)
        if errs:
            print("REFUSED: %d problem(s); NOTHING was written.\n" % len(errs)
                  + "\n".join("  - " + e for e in errs))
            return 2
        apply_to_ledger(rows, plan, run)

    print(json.dumps(write_journal(pkg, rows, plan, run), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
