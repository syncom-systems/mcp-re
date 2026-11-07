#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge-path gate — a control the assurance model relies on must run on the merge path.

THE FAILURE CLASS, which is the reason this file exists rather than any single instance:

    A security/assurance control relied upon by the assurance model must be mechanically
    present on the required merge path. Existence in a local-only aggregate such as
    `scripts/local_gate.sh` does not establish enforcement.

`local_gate.sh` is a convenience aggregate that a developer chooses to run. A control
reachable only from it is enforced by remembering to run it, which is the same standing as
no control at all — with the added cost that the repository, its docs and its reviewers all
believe the control is enforced. That belief is the damage: every claim above a control
reads as measured while nothing measured the change.

It has happened repeatedly and was never noticed by the thing that failed:

  * the two ADR-MCPRE-061 ratchets — a PR could grow a registered file or a lint baseline;
  * `verification_trigger_gate.py` — a PR narrowing the trigger filter also disabled the
    check that polices the filter;
  * `registry_approval_gate.py` — RED on `main`, with every CI check on every PR green;
  * the ten `tools/verification/test_*.py` suites, which are the assurance platform's own
    self-tests: nothing on the merge path established that the verdict algebra, the
    invalidation rules, the escape-hatch detector or the views generator still behave as
    the ADR says.

Each was repaired one at a time, by someone noticing. This gate is what notices.

WHAT IT PROVES: every script `local_gate.sh` invokes is named by at least one workflow
under `.github/workflows/`, or is exempt for a stated reason — AND that every control
invoked in COMMAND POSITION is executable in the index — AND that every ASSURANCE-PLATFORM
ENTRY POINT is reached by a workflow or by a dispatcher that one reaches.

THE DISCOVERY POPULATION IS A DEFINITION, which is the third half and the newest. The first
two sets are `local_gate.sh`'s invocations and `glob("tools/verification/test_*.py")`, and
NEITHER IS A DEFINITION — they are two places someone thought to look. That is not a
stylistic complaint; it is the measured reason this gate could not see its own blind spot.
`test_mutation_lane.py` was in neither set, and the repair was to add the second one: one
filename shape, closing one hole. The next shape was an extensionless entry point, and
`SELFTEST_GLOB` cannot match `check-generated`, `verify-tests` or `attest` any more than the
`local_gate.sh` scan could see a control that aggregate does not invoke.

So the population is defined rather than listed:

    An assurance-platform ENTRY POINT is an executable regular file directly under
    `tools/verification/` whose name does not begin with `_`.

The execute bit is the definition, and it is chosen because it is exactly what makes a file
invocable as a program — so the census is COMPLETE BY CONSTRUCTION. A new entry point cannot
be added without it (the `not_executable` half below already refuses one committed without
it), a leading underscore marks a module that is imported rather than run, and no filename
convention has to be remembered by anyone.

REACHED, not merely named. An entry point is on the merge path when an unconditional workflow
names it, or when a DISPATCHER that is itself reached runs it. There is one dispatcher:
`tools/verification/verify`, which runs the rows of the lane catalogue
`tools/verification/_lanes.py`, where a lane's entry point is written down. That table is
read by IMPORT rather than pattern-matched out of the file — a lane silently leaving
`LANES` is exactly the defect this half must catch, and a regex over the file would match
the line that remained in a comment.

Importing executes the catalogue's module level, which is pure: rows, derived sets and
asserts, with no import from the package. A gate that imported every control to discover
edges would be running them.

The second half is the same failure class read one step earlier. A control that cannot
START is not enforced, however many workflows name it, and the failure is not subtle when
it happens — `Permission denied`, stage 1, every run. It is subtle in the INDEX:
`tools/verification/evidence-class-census` landed at mode 100644, and nothing noticed,
because the gate above it matches only `.py` and `.sh` paths and every other control in
this repository happens to have been committed with its bit set. A path invoked as
`python3 x.py` needs no bit and is not asked for one; a path invoked as itself is.

A workflow must name its controls LITERALLY. This gate reads paths, so a step that
assembles a script name at run time — a shell loop over a list of suites, say — is a
control it cannot see, and an invisible control is how the next instance of this class
gets missed. Legibility to the checker is part of the enforcement.

WHAT IT DOES NOT PROVE: that the workflow naming it is a REQUIRED check, that the job runs
on every PR, or that the control is correct. Branch protection is repository configuration
and is not readable from the tree; this gate closes the gap it can see from here, which is
the one that has actually opened five times.

THE `scripts/` POPULATION IS THE GATE REGISTRY. `scripts/` has no property like the execute
bit that decides membership on its own: it holds gates, a sourced toolchain shim, a demo
runner, architecture reports and CI helpers, and executability separates none of them. So
membership is written down instead, in `config/gates.toml` (read by
`tools/verification/_gates.py`): every `scripts/*.py|*.sh` has a row, and a script with no
row fails here. Each row also states the `local_gate.sh` stages and the workflow jobs that
name the script, and this gate checks both against the files, so the registry cannot drift
from what actually runs. A row's `off_merge_path` is the one place an exemption from the
checks above is recorded, for a script and for an entry point alike.

Run:  python3 scripts/merge_path_gate.py
      python3 scripts/merge_path_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _merge_path.cli import judge  # noqa: E402
from _merge_path.config import (  # noqa: E402,F401
    ENTRY_ROOT,
    LOCAL_GATE,
    REPO,
    SELFTEST_GLOB,
    SHALLOW_FETCH,
    _gates,
)
from _merge_path.defects import (  # noqa: E402,F401
    defects,
    entry_point_defects,
    exemptions,
    registry_defects,
)
from _merge_path.extract import (  # noqa: E402,F401
    command_position_paths,
    invoked_by,
    names_in,
    not_executable,
    registry_paths,
    scripts_in,
    truncating_fetches,
)
from _merge_path.reach import (  # noqa: E402,F401
    dispatched_entry_points,
    entry_points,
    local_gate_stages,
    pull_request_reach,
    workflow_coverage,
    workflow_entry_coverage,
    workflow_jobs,
)
from _merge_path.selftest import selftest  # noqa: E402,F401
from workflow_reader import Command, Workflow, named_paths, parse, shell_commands, workflows  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    raise SystemExit(main())
