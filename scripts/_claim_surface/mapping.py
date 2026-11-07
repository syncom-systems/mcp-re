# SPDX-License-Identifier: Apache-2.0
"""Every way the registry's roots and the boundary's published claims can disagree."""

from __future__ import annotations

from _claim_surface.config import GAP_HEADER, SETTLED_HEADER
from _claim_surface.spec import Rows, Surfaces
from _claim_surface.standing import Standing


def _count_claims(claims: Rows) -> tuple[dict[str, int], list[str]]:
    """How many §2 rows name each theorem, and a defect per row that names none."""
    claimed: dict[str, int] = {}
    defects: list[str] = []
    for prose, named in claims:
        if not named:
            defects.append(
                f"§2 row names no theorem: {prose[:70]!r}. A claim with no root is a claim "
                f"this document is not entitled to make."
            )
            continue
        for theorem in named:
            claimed[theorem] = claimed.get(theorem, 0) + 1
    return claimed, defects


def _coverage_defects(declared: set[str], claimed: dict[str, int]) -> list[str]:
    """TOTAL, SOUND and UNIQUE: each declared root has exactly one claim row."""
    defects: list[str] = []
    for theorem in sorted(declared - set(claimed)):
        defects.append(
            f"{theorem} is a declared system root with no §2 claim row. A promise the "
            f"registry makes and the boundary does not publish is a claim no reader can "
            f"find, and the reader is who §2 is for."
        )
    for theorem in sorted(set(claimed) - declared):
        defects.append(
            f"§2 claims {theorem}, which `root_theorems` does not declare. Either the root "
            f"set is missing it or the claim is not one this document may make; the gate "
            f"will not guess which."
        )
    for theorem, count in sorted(claimed.items()):
        if count > 1:
            defects.append(
                f"{theorem} appears in {count} §2 rows. One root, one human claim: two "
                f"rows are two authorities over one promise, which is the condition this "
                f"gate exists to refuse."
            )
    return defects


def _theorem_disclaimer(
    theorem: str, area: str, declared: set[str], claimed: dict[str, int]
) -> list[str]:
    defects: list[str] = []
    if theorem in declared:
        defects.append(
            f"§4 lists {theorem} under {area!r} as an unclosed gap, but it is a "
            f"declared system root. A root is a promise the owner ratified; it "
            f"cannot also be an area in which this document makes no claim."
        )
    if theorem in claimed:
        defects.append(
            f"{theorem} is claimed in §2 and disclaimed in §4 under {area!r}. A "
            f"reader gets opposite answers depending which section they reach."
        )
    return defects


def _disclaimer_defects(
    area: str, named: list[str], declared: set[str], claimed: dict[str, int]
) -> list[str]:
    """DISJOINT: a theorem named by an open-gap row is neither a root nor a published claim."""
    defects: list[str] = []
    for theorem in named:
        defects += _theorem_disclaimer(theorem, area, declared, claimed)
    return defects


def _duplicate_area_defects(gaps: Rows) -> list[str]:
    """§4 SHAPE: no area is listed twice."""
    defects: list[str] = []
    seen: set[str] = set()
    for area, _ in gaps:
        key = area.strip().lower().strip("*")
        if key in seen:
            defects.append(
                f"§4 lists the area {area!r} more than once. The duplicate rows carried "
                f"different dispositions, so the answer a reader got depended on which row "
                f"they reached first."
            )
        seen.add(key)
    return defects


def _gap_defects(declared: set[str], claimed: dict[str, int], gaps: Rows) -> list[str]:
    """DISJOINT, and §4 SHAPE, over the open-gap rows."""
    defects: list[str] = []
    for area, named in gaps:
        defects += _disclaimer_defects(area, named, declared, claimed)
    return defects + _duplicate_area_defects(gaps)


def _staleness_defects(declared: set[str], claimed: dict[str, int], standing: Standing) -> list[str]:
    """NOT STALE: every claimed root is reviewed as it stands or carried by a correction."""
    defects: list[str] = []
    for theorem in sorted(claimed):
        if theorem not in declared:
            continue
        verdict = standing.unreviewed(theorem)
        if verdict is None:
            continue
        state, reason, why = verdict
        defects.append(
            f"§2 claims {theorem}, whose specification review is {state}: {reason}. A "
            f"published claim must be one the owner reviewed in its present form, or one a "
            f"RECORDED ADR-MCPRE-068 Phase-1 correction carries there from the fingerprint "
            f"they did review — and neither holds: {why}."
        )
    return defects


def _settled_defects(
    declared: set[str], claimed: dict[str, int], standing: Standing, settled: Rows
) -> list[str]:
    """A SETTLED row is the one place this gate cannot judge the prose.

    Whether an area was really closed is a review act. What it can judge is whether the
    row's own references hold up — a settled row naming a root that §2 does not publish
    would be recording a closure that did not happen, which is the failure this section was
    restructured out of.
    """
    defects: list[str] = []
    for area, named in settled:
        for theorem in named:
            if theorem in declared and theorem not in claimed:
                defects.append(
                    f"§4 records {area!r} as settled by {theorem}, a declared root that §2 "
                    f"does not publish. An area closed by a promise no reader can find is "
                    f"not closed."
                )
            if theorem not in standing.review_states:
                defects.append(
                    f"§4 records {area!r} as settled by {theorem}, which the registry does "
                    f"not declare. A closure resting on a theorem that does not exist is "
                    f"the stalest kind of green."
                )
    return defects


def _unknown_table_defects(unknown: list[str]) -> list[str]:
    return [
        f"§4 carries a table this gate cannot classify: {header!r}. A §4 table must "
        f"declare its kind in its header — {' | '.join(GAP_HEADER)} for open areas, "
        f"{' | '.join(SETTLED_HEADER)} for closed ones. An unclassifiable claim surface "
        f"must fail rather than read as an agreeing one."
        for header in unknown
    ]


def mapping_defects(roots: list[str], surfaces: Surfaces, standing: Standing) -> list[str]:
    """Every way the two surfaces can disagree. One function so the rules are one place."""
    declared = set(roots)
    claimed, defects = _count_claims(surfaces.claims)
    defects += _coverage_defects(declared, claimed)
    defects += _gap_defects(declared, claimed, surfaces.gaps)
    defects += _staleness_defects(declared, claimed, standing)
    defects += _settled_defects(declared, claimed, standing, surfaces.settled)
    defects += _unknown_table_defects(surfaces.unknown)
    return defects
