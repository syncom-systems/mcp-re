# SPDX-License-Identifier: Apache-2.0
"""Reading the guide's category table and the Bazel test declarations."""

from __future__ import annotations

import re
from pathlib import Path

from _conformance_claims.config import (
    BACKTICKED,
    BEGIN,
    END,
    GUIDE,
    ROW,
    SRCS_ENTRY,
    TARGET_NAME,
    TEST_BLOCK,
)

Row = tuple[str, str, list[str]]


def reaches(body: str, corpus_name: str) -> bool:
    """`true` iff a declaration's text names this corpus as a path.

    Matching the bare directory name would also match the target's own `name`
    field, which is how a harness that never sees the corpus would pass.
    """
    return re.search(rf"vectors/{re.escape(corpus_name)}\b", body) is not None


def recomputes_digest(package: Path, body: str) -> bool:
    """`true` iff a declaration's own sources mention `corpus_digest`.

    Which harness carries the pin is not fixed: two corpora are pinned by the
    shared `corpus_pinning_test`, a third by its own vector runner. What matters
    is that some test reaching the corpus recomputes the published digest.
    """
    for src in SRCS_ENTRY.findall(body):
        path = package / src
        if path.is_file() and "corpus_digest" in path.read_text(encoding="utf-8"):
            return True
    return False


def _claim_cells(line: str) -> list[str] | None:
    """The three cells of a claim row, or None for a line this gate does not read."""
    match = ROW.match(line.strip())
    if not match:
        return None
    cells = [c.strip() for c in match.group("cells").split("|")]
    if len(cells) != 3 or set(cells[0]) <= {"-", " ", ":"}:
        return None  # header separator, or a shape this gate does not read
    if cells[0].lower().startswith("category"):
        return None  # header row
    return cells


def parse_rows(guide_text: str) -> tuple[list[Row], list[str]]:
    """Return (rows, failures). A row is (category, corpus, [targets])."""
    if guide_text.count(BEGIN) != 1 or guide_text.count(END) != 1:
        return [], [
            f"{GUIDE}: expected exactly one {BEGIN} / {END} pair delimiting the "
            "category table"
        ]
    body = guide_text.split(BEGIN, 1)[1].split(END, 1)[0]
    rows: list[Row] = []
    for line in body.splitlines():
        cells = _claim_cells(line)
        if cells is None:
            continue
        category, corpus_cell, harness_cell = cells
        corpus = BACKTICKED.findall(corpus_cell)
        if len(corpus) != 1:
            return rows, [
                f"{GUIDE}: row {category!r} must name exactly one backticked corpus "
                f"path, found {corpus}"
            ]
        rows.append((category, corpus[0].rstrip("/"), BACKTICKED.findall(harness_cell)))
    if not rows:
        return [], [f"{GUIDE}: the category table has no rows — refusing to pass"]
    return rows, []


def declared_tests(root: Path) -> dict[str, tuple[Path, str]]:
    """Map `//pkg:target` to (package directory, declaration text)."""
    found: dict[str, tuple[Path, str]] = {}
    for build in sorted(root.glob("*/BUILD.bazel")):
        package = build.parent
        for block in TEST_BLOCK.finditer(build.read_text(encoding="utf-8")):
            body = block.group("body")
            name = TARGET_NAME.search(body)
            if name:
                found[f"//{package.name}:{name.group(1)}"] = (package, body)
    return found
