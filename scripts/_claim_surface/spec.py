# SPDX-License-Identifier: Apache-2.0
"""Reading the boundary spec: its numbered sections, and the §2 and §4 tables inside them."""

from __future__ import annotations

from dataclasses import dataclass, field

from _claim_surface.config import (
    BOUNDARY,
    GAP_HEADER,
    SECTION,
    SETTLED_HEADER,
    SUBSECTION,
    THM,
)

Rows = list[tuple[str, list[str]]]


@dataclass(frozen=True)
class Surfaces:
    """What the boundary spec publishes: claims, open gaps, settled record, unclassifiable tables."""

    claims: Rows
    gaps: Rows
    settled: Rows = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


def sections(text: str) -> dict[str, list[str]]:
    """The document split by top-level numbered section, subsections included with their parent.

    Subsections stay with the parent because §4.1 and §4.2 are amendments TO §4 and a
    theorem named in one is named in §4. Splitting them out would let a claim hide in an
    amendment.
    """
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = SECTION.match(line) or SUBSECTION.match(line)
        if heading:
            current = str(heading.group(1))
            found.setdefault(current, [])
        elif current is not None:
            found[current].append(line)
    return found


def table_rows(lines: list[str]) -> list[list[str]]:
    """The cells of every markdown table row in a section, header and rule excluded."""
    rows = (_cells(line.strip()) for line in lines)
    return [cells for cells in rows if cells and not _is_rule(cells)]


def _cells(stripped: str) -> list[str]:
    """The cells of a pipe-delimited line, or nothing when the line is not a table row."""
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _is_rule(cells: list[str]) -> bool:
    """The `|---|:--:|` rule under a header."""
    return all(set(cell) <= {"-", ":"} and cell for cell in cells)


def claim_rows(section2: list[str]) -> Rows:
    """`(claim prose, theorems named)` per §2 row, header dropped.

    The header is dropped by CONTENT rather than by position: a row whose second cell is
    literally the word `root` is the header, and a document that gained a leading note
    line would otherwise silently lose its first real claim from the gate's view.
    """
    rows = []
    for cells in table_rows(section2):
        if len(cells) < 2 or cells[1].lower() == "root":
            continue
        rows.append((cells[0], THM.findall(cells[1])))
    return rows


def split_section4(section4: list[str]) -> tuple[list[list[str]], list[list[str]], list[str]]:
    """§4's tables, separated by declared kind: `(open gaps, settled record, unrecognized)`.

    The third return value is the reason this returns three things. A table in §4 whose
    header matches neither known shape is not "no gaps found" — it is a table this gate
    cannot classify, and an unclassifiable claim surface must fail rather than read as an
    agreeing one. That is the same rule the rest of this platform applies to a lane that
    exits 0 without declaring a verdict.
    """
    gaps: list[list[str]] = []
    settled: list[list[str]] = []
    unknown: list[str] = []
    kinds = {GAP_HEADER: gaps, SETTLED_HEADER: settled}
    target: list[list[str]] | None = None
    for cells in table_rows(section4):
        header = tuple(cell.strip().lower().strip("*") for cell in cells)
        if header in kinds:
            target = kinds[header]
        elif cells[0].strip().lower() == "area":
            target = None
            unknown.append(" | ".join(cells))
        elif target is not None:
            target.append(cells)
    return gaps, settled, unknown


def gap_rows(section4: list[str]) -> Rows:
    """`(area, theorems the row is ABOUT)` per §4 OPEN-gap row.

    Two cells are read and the third deliberately is not. `area | disposition | placement`:
    the disposition names the area's OWN theorems and their state, and the placement names
    the root the area composes UNDER. A row saying "under THM-0077" is stating where an
    open gap attaches, not withholding THM-0077 — reading the placement cell as a
    disclaimer would make every correctly-placed gap row a contradiction, and a gate that
    fires on correct prose is a gate the next author routes around.

    Rows whose disposition places the area outside the runtime roots are not open gaps at
    all: "deployment rendering" and "the assurance platform" say where a concern is owned,
    and §0 governs them.
    """
    rows = []
    for cells in split_section4(section4)[0]:
        if len(cells) < 2:
            continue
        disposition = cells[1]
        if "outside" in disposition.lower():
            continue
        rows.append((cells[0], THM.findall(f"{cells[0]} {disposition}")))
    return rows


def settled_rows(section4: list[str]) -> Rows:
    """`(area, theorems named)` per §4 SETTLED row — an area the ruling closed."""
    return [
        (cells[0], THM.findall(" ".join(cells)))
        for cells in split_section4(section4)[1]
        if len(cells) >= 2
    ]


def read_surfaces() -> Surfaces:
    """The boundary spec's claims, open gaps, settled record and unclassifiable tables."""
    parts = sections(BOUNDARY.read_text(encoding="utf-8"))
    if "2" not in parts or "4" not in parts:
        raise SystemExit(
            f"FAIL: {BOUNDARY} has no §2 or no §4. The gate reads those sections by "
            f"number; a renumbered document must update this gate rather than silently "
            f"measure nothing."
        )
    return Surfaces(
        claim_rows(parts["2"]),
        gap_rows(parts["4"]),
        settled_rows(parts["4"]),
        split_section4(parts["4"])[2],
    )
