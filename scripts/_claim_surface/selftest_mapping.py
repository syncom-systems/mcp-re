# SPDX-License-Identifier: Apache-2.0
"""Selftest: the mapping rules refuse each way the two surfaces can disagree, and the parsers read."""

from __future__ import annotations

from _claim_surface.mapping import mapping_defects
from _claim_surface.spec import Surfaces, claim_rows, gap_rows, sections, settled_rows, split_section4
from _claim_surface.standing import Standing

from _review import REVIEWED  # noqa: E402

REVIEWED_STATES = {t: (REVIEWED, "reviewed") for t in ("THM-0001", "THM-0002", "THM-0003")}

#: `(roots, claims, gaps, review states, expected defect fragment or None, label)`.
MAPPING_CASES: list[tuple[list, list, list, dict, str | None, str]] = [
    (["THM-0001"], [("a claim", ["THM-0001"])], [], REVIEWED_STATES,
     None, "a root with exactly one claim"),
    (["THM-0001", "THM-0002"], [("a claim", ["THM-0001"])], [], REVIEWED_STATES,
     "THM-0002 is a declared system root with no §2 claim row",
     "a root the boundary does not publish"),
    (["THM-0001"], [("a claim", ["THM-0001"]), ("another", ["THM-0002"])], [], REVIEWED_STATES,
     "which `root_theorems` does not declare", "a claim with no root"),
    (["THM-0001"], [("a claim", ["THM-0001"]), ("said twice", ["THM-0001"])], [], REVIEWED_STATES,
     "appears in 2 §2 rows", "one root claimed twice"),
    (["THM-0001"], [("a claim", ["THM-0001"])], [("some area", ["THM-0001"])], REVIEWED_STATES,
     "declared system root", "a root listed as an open gap"),
    (["THM-0001"], [("a claim", ["THM-0001"])], [("dup", []), ("Dup", [])], REVIEWED_STATES,
     "more than once", "a duplicated §4 area"),
    (["THM-0001"], [("a claim", ["THM-0001"])], [],
     {"THM-0001": ("STALE_CLAIM", "the statement moved")},
     "specification review is STALE_CLAIM", "a claim whose review went stale"),
    (["THM-0001"], [("a claim", [])], [], REVIEWED_STATES,
     "names no theorem", "a §2 row naming nothing"),
]

DOC2 = "## 2. Claims\n\n| claim | root |\n|---|---|\n| prose here | **THM-0074** — x |\n"
DOC4 = (
    "## 4. Gaps\n\n| area | disposition | placement |\n|---|---|---|\n"
    "| Replay | in scope — THM-0086 | under THM-0077 |\n"
    "| Rendering | **outside** the runtime roots | release gates |\n"
    "\n### 4.3 Settled\n\n| area | settled as | route |\n|---|---|---|\n"
    "| Sidecar | **§2 claim** — THM-0091 | established and reviewed |\n"
)


def check_mapping_cases() -> str | None:
    for roots, claims, gaps, reviews, needle, label in MAPPING_CASES:
        found = mapping_defects(roots, Surfaces(claims, gaps), Standing(reviews))
        if needle is None:
            if found:
                return f"refused {label}: {found}"
        elif not any(needle in entry for entry in found):
            return f"accepted {label}: {found}"
    return None


# The parsers are half the gate. A table reader that stopped matching would report an
# empty surface as a consistent one, which is "exits 0 having measured nothing" wearing
# this gate's name.
def check_claim_reader() -> str | None:
    parsed = claim_rows(sections(DOC2)["2"])
    if parsed != [("prose here", ["THM-0074"])]:
        return f"the §2 reader parsed {parsed!r}"
    return None


def check_gap_reader() -> str | None:
    # THM-0077 is in the PLACEMENT cell — where the gap attaches, not what it withholds.
    # THM-0091 is in the SETTLED table, which is a different kind of row entirely. A reader
    # of this test should see both omissions as the point of it.
    parsed = gap_rows(sections(DOC4)["4"])
    if parsed != [("Replay", ["THM-0086"])]:
        return f"the §4 reader parsed {parsed!r}"
    return None


def check_settled_reader() -> str | None:
    parsed = settled_rows(sections(DOC4)["4"])
    if parsed != [("Sidecar", ["THM-0091"])]:
        return f"the settled reader parsed {parsed!r}"
    return None


def check_orphan_settled_row() -> str | None:
    """A settled row naming a root §2 does not publish records a closure that did not happen."""
    orphan = mapping_defects(
        ["THM-0001", "THM-0091"],
        Surfaces([("a claim", ["THM-0001"])], [], [("Sidecar", ["THM-0091"])]),
        Standing({**REVIEWED_STATES, "THM-0091": (REVIEWED, "reviewed")}),
    )
    if not any("does not publish" in entry for entry in orphan):
        return "accepted a settled row closing on an unpublished root"
    return None


def check_unclassifiable_table() -> str | None:
    """A §4 table declaring neither kind must fail, not read as an empty gap list."""
    strange = "## 4. Gaps\n\n| area | something else |\n|---|---|\n| X | Y |\n"
    if not split_section4(sections(strange)["4"])[2]:
        return "an unclassifiable §4 table read as no gaps"
    return None


def check_amendment_folds_into_parent() -> str | None:
    """A subsection's theorems belong to its parent, or a claim could hide in an amendment."""
    nested = "## 4. Gaps\n\n### 4.1 Amendment\n\n| area | in scope — THM-0091 |\n|---|---|\n"
    if "4" not in sections(nested) or "THM-0091" not in " ".join(sections(nested)["4"]):
        return "a §4.1 amendment did not fold into §4"
    return None


CHECKS = (
    check_mapping_cases,
    check_claim_reader,
    check_gap_reader,
    check_settled_reader,
    check_orphan_settled_row,
    check_unclassifiable_table,
    check_amendment_folds_into_parent,
)
