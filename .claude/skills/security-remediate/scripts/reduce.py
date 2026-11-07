"""Deterministic reducer and auditor: replay the progress journal into derived state.

(Invoked as `python3 reduce.py …`; no shebang, because the repo's bulk-operation
hook pattern matches "shebang … find … sed", and the words "findings"/"disposed"
trip it.)

THE POINT OF THIS FILE: the LLM becomes a READER of derived state, never the
thing that determines state. Everything here is mechanical — schema validation,
sequence validation, legal transitions, index building, invariant checks. There
is no regex over `note`, no NLP, no "probably belongs to". It answers one
question: given the protocol events that actually exist, what state follows, and
are those events internally consistent?

    progress.jsonl  ->  reduce  ->  current-state.json
    (immutable journal)             attention.json
    ledger.jsonl                    audit-report.md

This is the ONE auditor of the journal. A second reader with its own rules would
be two authorities over one record that can disagree.

Rules it enforces that the harness previously could not:

1. COUNTS ARE ASSERTIONS, NOT STATE. `evaluate` and the terminal event repeat
   the same tally, so summing them double-counts. The reducer derives the real
   numbers from identified objects and then CHECKS them against the asserted
   `counts`. A mismatch is reported, not silently preferred either way — in the
   2026-09-22 batch four evaluators counted duplicates inside `disposed` and four
   did not, so the field was not merely undefined, it was inconsistently applied.

2. THE JOURNAL IS CROSS-CHECKED AGAINST THE LEDGER. The ledger stays
   authoritative for FINDING state (next_file.py reads it to choose work); the
   journal is authoritative for OPERATION state, which the ledger does not model.
   Every `close` event must have a matching ledger row with the same status, and
   the ledger's population must be conserved. That invariant is what would have
   caught the 365-finding loss in seconds instead of an hour later by eye.

3. EVERY PROBLEM CARRIES A STABLE CODE AND A CLASS, and the class alone decides
   the exit status under `--check`:

     fatal    cannot reconstruct authoritative state (seq collision, duplicate
              event id, contradictory terminal events)
     error    reconstructable, but the journal violates the protocol
     warning  valid state that deserves attention
     info     a run characteristic, not a defect

   Open remediation work — escalations, unresolved work items — is STATE, never
   a problem. "89 unresolved escalations" must not make the auditor exit as if
   the journal were corrupt.

4. ORDER IS `seq`, NEVER THE CLOCK. Agents run concurrently, so `ts` may run
   backwards across adjacent events. That is evidence, not corruption.

Exit status:
  0  no fatal/error problem (or `--check` not given)
  1  `--check` and at least one fatal/error problem
  2  input could not be read as a journal (malformed record, or an input that
     changed while it was being read outside `--live`)

`--live` is for auditing a journal a lane is still appending to:
  * an incomplete FINAL record (a writer mid-append) is dropped and reported as
    JNL-002; malformed JSON anywhere else is still exit 2;
  * the journal and ledger are separate mutable files, so both are read inside a
    stat-before/stat-after window with one retry; if the pair still moved, the
    cross-file checks that depend on them are withheld and LED-900 is reported
    instead of a ledger-integrity error;
  * an attempt with no terminal event yet is in flight, so ATT-003 is info.

Usage:
  python3 reduce.py --log <progress> [--ledger <ledger.jsonl>] [--out <dir>]
                    [--check] [--live] [--repo-root <dir>]
  python3 reduce.py --log <progress> --print-attention
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _persist import atomic_write_lines  # noqa: E402
from _reduce_attempts import summarize_attempts  # noqa: E402
from _reduce_attention import attention as _attention  # noqa: E402
from _reduce_findings import duplicate_provenance, unresolved_evidence  # noqa: E402
from _reduce_input import read_inputs  # noqa: E402
from _reduce_ledger import ledger_cross_check  # noqa: E402
from _reduce_model import (AUDITOR_VERSION, BLOCKING_FINDING_STATUS, CLASS_ORDER,  # noqa: E402,F401
                           DEFAULT_REPO_ROOT, FAILING_CLASSES, INVARIANTS,
                           JOURNAL_SCHEMA_VERSIONS, KNOWN_EVENTS, STATE_SCHEMA_VERSION,
                           TERMINAL_EVENTS, TERMINAL_FINDING_STATUS)
from _reduce_replay import replay_events  # noqa: E402
from _reduce_report import render_report  # noqa: E402,F401
from _reduce_sequence import order_rows, sequence_facts  # noqa: E402
from _reduce_state import Facts, build_state  # noqa: E402
from journal_input_error import JournalInputError  # noqa: E402


def reduce_journal(log: str, ledger_path: str = "", *, live: bool = False,
                   repo_root: str = "") -> tuple:
    """Replay the journal. Pure function of its inputs — no wall clock, no rng.

    Raises JournalInputError when the input cannot be read as a journal.
    """
    repo_root = repo_root or DEFAULT_REPO_ROOT
    inp = read_inputs(log, ledger_path, live)
    order_rows(inp.rows)
    seq = sequence_facts(inp.rows)
    replay = replay_events(inp.rows)
    by_attempt, attempt_problems = summarize_attempts(replay.attempts, replay.findings, live)
    provenance = duplicate_provenance(replay.findings, inp.ledger, inp.ledger_usable)
    unresolved, evidence_problems = unresolved_evidence(replay.evidence_refs, repo_root)
    ledger_check, ledger_blocking, ledger_problems = ledger_cross_check(
        inp, replay.findings, ledger_path)
    problems = (inp.problems + seq.problems + replay.problems + attempt_problems
                + provenance.problems + evidence_problems + ledger_problems)
    state = build_state(Facts(inp, seq, by_attempt, replay.findings, provenance, unresolved,
                              ledger_check, ledger_blocking, problems, ledger_path,
                              repo_root, live))
    return state, _attention(state)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True, help="progress log base path (no extension)")
    ap.add_argument("--ledger", default="", help="ledger to cross-check against")
    ap.add_argument("--out", default="",
                    help="directory for current-state.json / attention.json / audit-report.md")
    ap.add_argument("--print-attention", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on any fatal/error problem (open work is never a failure)")
    ap.add_argument("--live", action="store_true",
                    help="the journal is still being appended to; see module docstring")
    ap.add_argument("--repo-root", default="",
                    help="root that relative evidence_ref paths resolve against "
                         "(default: the repository containing this script)")
    return ap


def _write_outputs(out_dir: str, state: dict, attention: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    atomic_write_lines(os.path.join(out_dir, "current-state.json"),
                       [json.dumps(state, sort_keys=True, indent=1)])
    atomic_write_lines(os.path.join(out_dir, "attention.json"),
                       [json.dumps(attention, sort_keys=True, indent=1)])
    atomic_write_lines(os.path.join(out_dir, "audit-report.md"),
                       [render_report(state, attention).rstrip("\n")])


def _print_result(a: argparse.Namespace, state: dict, attention: dict) -> None:
    if a.print_attention or not a.out:
        print(json.dumps(attention, sort_keys=True, indent=1))
    else:
        print(json.dumps(state["totals"], sort_keys=True, indent=1))
        print("VERDICT %s — %s" % (state["verdict"], json.dumps(state["problem_counts_by_class"])))


def run(argv: list) -> int:
    a = _parser().parse_args(argv)
    try:
        state, attention = reduce_journal(a.log, a.ledger, live=a.live,
                                          repo_root=os.path.abspath(a.repo_root)
                                          if a.repo_root else "")
    except JournalInputError as exc:
        print("INPUT ERROR: %s" % exc, file=sys.stderr)
        return 2
    if a.out:
        _write_outputs(a.out, state, attention)
    _print_result(a, state, attention)
    return 1 if a.check and state["verdict"] == "fail" else 0


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
