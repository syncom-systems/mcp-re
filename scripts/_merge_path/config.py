# SPDX-License-Identifier: Apache-2.0
"""The gate's constants and the registry reader it judges against."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOCAL_GATE = REPO / "scripts" / "local_gate.sh"

sys.path.insert(0, str(REPO / "tools" / "verification"))
import _gates  # noqa: E402,F401

#: A fetch that TRUNCATES the object graph rather than extending it.
#:
#: `git fetch --depth=N` into a full clone does not add a ref beside the history; it makes
#: the repository SHALLOW at that commit, and every later step that asks an ancestry
#: question gets the wrong answer. That is not a local mistake: it took the R9 linkage
#: control down with it, reporting all 56 recorded closure commits — present in the clone —
#: as merges the tree does not contain.
#:
#: Refused only in a job that checked out at `fetch-depth: 0`, because that job asked for
#: the full history on purpose and something later reads it. A job that never had the
#: history is free to fetch what it needs.
SHALLOW_FETCH = re.compile(r"git fetch\b[^\n]*(--depth[= ]|--shallow-since|--shallow-exclude)")

#: The assurance platform's own self-tests. They are what establishes that a `verify`
#: verdict means what ADR-MCPRE-059 says it means, so every product claim rests on them —
#: which is why their scope here is NOT "whatever local_gate.sh happens to invoke". A
#: suite nobody wired into either aggregate would otherwise be enforced by nothing and
#: visible to nothing, and that is exactly how `test_mutation_lane.py` came to be neither.
SELFTEST_GLOB = "tools/verification/test_*.py"

#: Where the assurance platform's entry points live. One directory, because that is what
#: "the assurance platform" means in this tree and a definition that ranged wider would be
#: a guess about where the next one might go.
ENTRY_ROOT = "tools/verification"

#: A shell function definition, and a `local_gate.sh` stage: the `run "<label>" <function>`
#: lines, numbered in the order they appear, which is the order the aggregate runs them.
FUNCTION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", re.M)
STAGE = re.compile(r'^run\s+"[^"]*"\s+([A-Za-z_][A-Za-z0-9_]*)\s*$', re.M)
