#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge-readiness gate — the sole authority for whether a candidate SHA may merge.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    A merge authorized by anything weaker than "every lane the affected verification-unit
    closure requires COMPLETED SUCCESSFULLY at this exact SHA".

The instance: #945 merged while its `verification platform` lane had never executed at its
SHA. Every step of that was individually defensible — the required-check set was green, the
lane is not in `Protect main`, and a human read a status list and saw nothing red. What was
missing is that *nothing red* and *everything required, measured, here* are different
propositions, and only the second authorizes a merge. A queued lane is not a green one; an
absent check is not a passing one; a check green at a DIFFERENT commit says nothing about
this one.

WHY A CONTROL AND NOT A CONVENTION. The weaker query is always available and always easier:
`gh pr checks` prints a list a reader summarises, and summarising is where the four
distinctions below are lost. So this gate does not advise — it answers, and the answer
carries no raw material for a caller to re-interpret.

THE STATES ARE FOUR, AND THE RULE OVER THEM IS ONE:

    READY        every lane the governing authority requires is completed/success HERE
    NOT_READY    the measurement is incomplete — wait, or re-run
    FAILED       a lane's OWN verdict establishes that it failed — fix
    UNDECIDABLE  the gate cannot answer; it says why

    ONLY `READY` PERMITS A MERGE. Every other state refuses.

`UNDECIDABLE` is kept rather than folded into `NOT_READY` because the two call for
different actions: one is waiting, the other is a question about the gate's own inputs.
Neither permits a merge, so the distinction is diagnostic and never permissive.

ATTRIBUTION, WHICH IS WHY `FAILED` IS NARROW. One job — the umbrella `verify` — runs
several lanes. Its verdict is therefore attributable to a LANE only in one direction:

    umbrella completed/success       may satisfy every lane it actually contains
    umbrella pending or unavailable  those lanes are NOT_READY
    umbrella FAILURE                 says nothing about WHICH lane failed

A lane is `FAILED` only where a check whose verdict IS that lane's own establishes it —
which means a dedicated, single-lane job. Reporting "the V0 test lane failed" because an
unrelated Lean or extraction step went red inside the umbrella would be a fabricated
verdict, and it would send someone to fix a lane that never ran badly. The umbrella's
failure still refuses the merge; it refuses as NOT_READY, with the reason saying so.

WHAT "REQUIRED" MEANS HERE, and where it comes from. Not a list in this file. A second list
of required evidence is the defect it would exist to prevent: it would drift from the
manifest silently and in the direction that produces a false ready. The chain is derived,
end to end, from authorities that already govern the campaign:

    changed files          git diff against the merge base
      -> affected units    `verification.toml` unit `paths`, widened by the workspace
                           build inputs and closed forward over prerequisite edges
      -> required lanes    `_evidence.required_lanes` — the lanes a unit's declared
                           `evidence` URIs claim
      -> required checks   `_lanes.LANES` names each lane's script; the workflows name
                           which job runs that script, or the umbrella `verify` that
                           contains it. The job's `name:` IS the check name GitHub reports.

WHICH OF THOSE STEPS IS BOUND TO THE CANDIDATE, stated because a reader who assumes "all of
them" would be wrong. The ESTATE is: `manifest_at(sha)` reads
`verification/policy/verification.toml` out of the candidate commit, so which units a change
affects and which lanes they require are the candidate's own facts. The LANE-TO-CHECK
MAPPING is not: `_lanes.LANES` and `.github/workflows/*.yml` are read from the WORKING TREE,
so a candidate that renames a lane, moves a lane's script, or renames the job that runs it is
mapped through the tree's spelling of those names rather than its own. That gap is known and
not closed here. Most of its shapes are conservative — a lane the tree cannot name, or whose
script no workflow job invokes, raises `Undecidable` rather than resolving to nothing, and a
job the tree names differently from the candidate reads as a MISSING check, which is
NOT_READY. The shape that is not conservative is a disagreement about WHICH job runs a lane:
where the tree maps a lane to the umbrella `verify` and the candidate has moved that lane
out to a job of its own, a green umbrella satisfies a lane that job never measured.

THE FOUR CONDITIONS, per required check. All four, or the check is not satisfied:

    the check EXISTS for this SHA
    its head_sha == the candidate SHA
    its status == "completed"
    its conclusion == "success"

Everything else is NOT READY — missing, queued, pending, in_progress, a null or empty
conclusion, cancelled, skipped, timed_out, neutral. `failure` and `timed_out` are reported
as FAILED rather than NOT_READY because they are verdicts about the code and the next
action differs: NOT_READY means wait or re-run, FAILED means fix.

WHAT A PULL REQUEST CAN BE ASKED FOR. Only what a pull request starts. The complete
verification run starts on schedule and dispatch alone (`docs/dev/ci-scheduling.md`), so a lane
that only it executes has no pre-merge check: the gate lists it as DEFERRED and neither
requires it (that would block every merge on a run nobody started) nor counts it satisfied
(that would claim a measurement). A change that moved every fingerprint therefore reads READY
once the bounded checks pass, and the report says plainly that the evidence is stale until the
complete run. A lane served by a path-filtered pull-request workflow is required only when
the filter matches a changed file.

THE BRANCH RULESET IS ALWAYS REQUIRED. A change can touch no declared unit at all — a gate
script, a workflow, a document — and answering READY on an empty closure would be the
emptiest false green available: "no lane was required" and "every required lane passed" are
different facts. The ruleset is read from where it actually lives, the repository's own branch
ruleset via the API. That is not a second list: it is not maintained here, and a required
check added or renamed in the ruleset is picked up on the next run. The closure's pre-merge
lane checks are added to it.

Every check answers the same four conditions and the same three states, and the report says
which authority it used.

WHAT THIS DOES NOT PROVE: that the required lanes are the right ones (that is the manifest's
claim), that a passing lane measured what it says (that is the lane's), or that the lane
names and job names it resolves through are the candidate's rather than the tree's. It
proves that the checks the governing authority asks for, named as the working tree names
them, have completed successfully at this exact commit.

Run:  python3 scripts/merge_readiness_gate.py --sha <candidate>
      python3 scripts/merge_readiness_gate.py --pr 946
      python3 scripts/merge_readiness_gate.py --selftest

Exit status: 0 READY, 1 NOT_READY, 2 FAILED, 3 UNDECIDABLE.
Only 0 permits a merge, and `scripts/merge_verified_pr.py` is the only thing that acts
on it — see that file for why the decision has to be re-bound to the head it was made about.
"""

from __future__ import annotations

import sys

from _merge_readiness.candidate import (
    VERIFICATION_TOML,
    changed_files,
    check_runs,
    gh_json,
    git,
    manifest_at,
    ruleset_required_checks,
)
from _merge_readiness.cli import parser, run
from _merge_readiness.derivation import (
    UMBRELLA,
    WORKFLOWS,
    checks_for_lanes,
    lane_scripts,
    pull_request_workflows,
    umbrella_checks,
    workflow_jobs,
)
from _merge_readiness.errors import Undecidable
from _merge_readiness.paths import REPO
from _merge_readiness.report import Outcome, report
from _merge_readiness.selftest import selftest
from _merge_readiness.verdict import (
    FAILED,
    FAILING_CONCLUSIONS,
    NOT_READY,
    READY,
    classify,
    decide,
    skipped_by_itself,
)

__all__ = [
    "FAILED",
    "FAILING_CONCLUSIONS",
    "NOT_READY",
    "READY",
    "REPO",
    "UMBRELLA",
    "VERIFICATION_TOML",
    "WORKFLOWS",
    "Outcome",
    "Undecidable",
    "changed_files",
    "check_runs",
    "checks_for_lanes",
    "classify",
    "decide",
    "gh_json",
    "git",
    "lane_scripts",
    "main",
    "manifest_at",
    "pull_request_workflows",
    "report",
    "ruleset_required_checks",
    "selftest",
    "skipped_by_itself",
    "umbrella_checks",
    "workflow_jobs",
]


def main(argv: list[str]) -> int:
    args = parser(__doc__.splitlines()[0]).parse_args(argv)
    if "--selftest" in argv:
        return selftest()
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
