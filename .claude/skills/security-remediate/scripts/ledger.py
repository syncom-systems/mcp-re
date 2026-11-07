#!/usr/bin/env python3
"""Finding ledger + reconcile for the security-audit-funnel.

A finding ledger is the durable, version-controlled record of every audit finding
ever seen for a target and how it was DISPOSITIONED, so a later round never re-pays
the expensive Stage-3 verify cost on a finding already adjudicated. The ledger is a
JSONL file (one finding per line) checked into the audited repo (e.g.
`docs/security/finding-ledger.jsonl`); git history is the audit trail.

Disposition taxonomy (`status`):
  open              active, real, tracked — re-surface as "already tracked"
  escalated / needs-senior-eval   waiting on a decision; counted open
  fixed             remediated in code (carry the commit) — re-surface = REGRESSION (loud)
  false-positive    adjudicated not a real defect
  premise           the finding is the statement of a registered assumption; `premise`
                    names its ASM id in verification/policy/assumptions.toml
  constraint        a demonstrated architectural constraint an owner ruling accepted;
                    `owner_ruling` names the ruling ("Ruling 22.1")
  superseded        the finding's location no longer exists (code removed/relocated)
  duplicate         another observation of a finding named by `duplicate_of`
  positive-control  an INFO finding confirming a good control is present
  informational     an info-severity finding kept off the remediation worklist
  handled-prior-round   filed + closed in a prior round, exact resolution not re-derived

`accepted-risk` and `wontfix` are not dispositions: a real security defect is fixed,
disproved, or stays open. `set` refuses them, `check` fails on any row carrying them,
and `stats` counts every row that is not validly closed as open — a `premise` naming no
registered assumption and a `constraint` naming no owner ruling included.

`verified.method` records HOW a disposition was reached — never overclaim:
  gate-3skeptic | manual-source | fix-merged | review-adjudicated | intentional-posture
  | closed-issue | removed-code

Fingerprint (`id`): sha1(file-basename | sorted significant title tokens). Line
numbers and exact wording drift between rounds, so the id is deliberately coarse;
reconcile() ALSO emits fuzzy candidate matches (same file+category) that a human/LLM
must confirm rather than silently suppressing them.

Subcommands:
  fingerprint  --file F --title T
  ingest       LEDGER PRERUN --round R [--status S] [--method M]
  reconcile    LEDGER PRERUN
  set          LEDGER --id ID [--status S] [--method M] [--issue N] [--pr N] [--note ..]
               [--premise ASM-NNNN] [--owner-ruling "Ruling N"]
  stats        LEDGER [--assumptions TOML]
  check        LEDGER [--assumptions TOML]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ledger_cli import build_parser  # noqa: E402
from _ledger_commands import cmd_check, cmd_fingerprint, cmd_set, cmd_stats  # noqa: E402,F401
from _ledger_identity import _basename, _file_of, _findings_of, _norm_tokens, fingerprint  # noqa: E402,F401
from _ledger_ingest import _count_by, cmd_ingest, cmd_reconcile  # noqa: E402,F401
from _ledger_store import _load, _save  # noqa: E402,F401
from _ledger_taxonomy import (  # noqa: E402,F401 — callers and the tests read these from `ledger`
    ASSUMPTIONS_TOML, CLOSED_STATUSES, OPEN_STATUSES, REFUSED_STATUSES, SUPPRESS,
    closure_problem, is_open, registered_assumptions)


def main():
    a = build_parser(__doc__).parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
