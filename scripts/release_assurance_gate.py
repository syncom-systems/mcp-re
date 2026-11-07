#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release-assurance gate — the canonical command has a caller, and the document has a record.

THE FAILURE CLASS THIS EXISTS FOR, measured on 2026-09-14:
`tools/verification/review --require-root-complete` is the BINDING closure mode named by
#542 as a done criterion, and it had **zero invokers** — zero shell scripts, zero
workflows. Every occurrence in the tree was prose about the flag. It had been run by hand
for v0.16 and v0.17 and its verdict typed into a provenance document.

A tool with no caller is the false-green class this repository has now recorded three
times: `too-many-lines-threshold` parameterising a lint nobody switched on, a documented
SLO-Job rehearsal with no caller, and this. So the repair is not only to write the command
— it is to make its absence fail.

WHAT THIS PROVES, exactly, in two halves:

1. **INVOCATION.** The release workflow calls `tools/verification/release-assurance` in
   COMMAND POSITION. A mention in a comment or a `name:` is not a call, and this gate's own
   docstring names the path — so a mention-based reading would let the gate satisfy its own
   requirement by describing it.

2. **CORRESPONDENCE.** A release provenance document does not get to state the assurance
   verdict on its own authority. Every document under `docs/releases/` is registered here
   with how its assurance claim is backed, and an UNREGISTERED document is refused: a claim
   this gate has not been taught to check is a claim nobody checks.

3. **PROVENANCE.** A `workflow_dispatch` runs the workflow file of the branch it was
   dispatched from, so a writer can dispatch a branch whose copy of the workflow drops the
   reachability guard and uploads a plausible record. What GitHub itself records about a run
   -- its workflow path, its branch, its event -- cannot be edited from a branch. So a
   mechanized record must name its producing run as `release.yml@refs/heads/main` (the v0.18.0
   record, produced before the rename, names `release-assurance.yml@refs/heads/main`; that one
   path is accepted for the documents in LEGACY_PRODUCED only) (checked offline, on every CI run), and `--verify-run RECORD` asks GitHub about that run
   and compares the run's own uploaded record with the file before it is committed: the
   run must be this workflow, on `main`, a successful dispatch, and its artifact must be
   byte-identical to the record.

WHAT IT DOES NOT PROVE. That the release workflow was ever RUN, or that it passed. That is
what the record the workflow uploads is for, and reachability is the half that had actually
come loose.

Run:  python3 scripts/release_assurance_gate.py
      python3 scripts/release_assurance_gate.py --selftest
      python3 scripts/release_assurance_gate.py --verify-run docs/releases/<v>-release-assurance.json
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _release_assurance.cli import run  # noqa: E402
from _release_assurance.config import (  # noqa: E402,F401
    BACKING,
    CANONICAL,
    LEGACY_PRODUCED,
    LEGACY_PRODUCER_REF_SUFFIX,
    LEGACY_WORKFLOW,
    MARKER_BEGIN,
    MARKER_END,
    PRODUCER_REF_SUFFIX,
    RELEASES,
    REPO,
    WORKFLOW,
)
from _release_assurance.correspondence import correspondence_problems  # noqa: E402,F401
from _release_assurance.invocation import invocation_problems, invoked  # noqa: E402,F401
from _release_assurance.provenance import (  # noqa: E402,F401
    gh_artifact,
    gh_run,
    run_provenance_problems,
    verify_run,
)
from _release_assurance.records import (  # noqa: E402,F401
    block_of,
    load_record,
    load_record_obj,
    producer_problems,
    record_name,
    render,
)
from _release_assurance.selftest import selftest  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
