# SPDX-License-Identifier: Apache-2.0
"""The gate's constants: where the boundary spec is, how its sections read, what it is measured against."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BOUNDARY = REPO / "docs" / "spec" / "security-boundary.md"

# The registry readers live beside the verification tools, not beside this gate.
sys.path.insert(0, str(REPO / "tools" / "verification"))

#: A theorem reference anywhere in the document.
THM = re.compile(r"THM-\d{4}")

#: The heading that opens each section this gate reads. Matched on the NUMBER, not the
#: title: the titles are prose the owner may reword, and a gate that broke on a reworded
#: heading would be a gate people route around.
SECTION = re.compile(r"^## (\d+)\. ")
SUBSECTION = re.compile(r"^### (\d+)\.(\d+) ")

#: The header a §4 table must carry to be read as one kind or the other. A table DECLARES
#: which it is; the gate never infers it from the prose in a disposition cell. Inference was
#: tried and is wrong twice over: it makes the gate fire on a correctly-worded settled row,
#: and it lets a badly-worded open gap escape by not containing whatever word the matcher
#: happened to look for. A header is a structural statement the author must make on purpose.
GAP_HEADER = ("area", "disposition", "placement")
SETTLED_HEADER = ("area", "settled as", "route")

#: The branch this gate measures claim movement against. Named once so the selftest and the
#: prose agree with the code about which ref is the baseline.
MOVEMENT_REF = "origin/main"

#: How each moved-claim component reads to someone who has to act on the defect.
COMPONENT_PROSE = {
    "theorem_claim": "its own statement, security consequence or scope",
    "theorem_dependencies": "a premise beneath it",
    "theorem_review_requirement": "who must review it",
}
