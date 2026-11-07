# SPDX-License-Identifier: Apache-2.0
"""The production view of a Rust source: its lines outside every test region."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from _rust_source_lex import code_only

#: ADR-MCPRE-061 §5.1. Both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

#: The inner form: a file whose first code line is `#![cfg(test)]` is test code throughout.
TEST_FILE_ATTR = re.compile(r"^#!\[cfg\((all\()?test\b")


def _is_test_file(code_lines: list[str]) -> bool:
    """Whether the first line carrying code is the whole-file `#![cfg(test)]` attribute."""
    first = next((line.strip() for line in code_lines if line.strip()), "")
    return bool(TEST_FILE_ATTR.match(first))


def _closes_region(opened: bool, depth: int, code: str) -> bool:
    """A braced item closes when its braces balance; a braceless one at its `;`."""
    return depth <= 0 and (opened or ";" in code)


def _region_end(code_lines: list[str], start: int) -> int:
    """The index just past the test region whose attribute is at `start`.

    `code_lines` is the file with comments and literals already blanked, so every brace
    and `;` seen here is code. A braced item ends at its matching close; an item that
    reaches `;` before any brace ends there, so the next item stays production.
    """
    depth, opened, i = 0, False, start
    while i < len(code_lines):
        code = code_lines[i]
        depth += code.count("{") - code.count("}")
        opened = opened or "{" in code
        i += 1
        if _closes_region(opened, depth, code):
            return i
    return i


@dataclass(frozen=True)
class ProductionView:
    """The production lines of one Rust source, each with its 1-based line number."""

    lines: tuple[tuple[int, str], ...]

    def __len__(self) -> int:
        return len(self.lines)

    def text(self) -> str:
        """The production lines as written, joined."""
        return "\n".join(line for _, line in self.lines)

    def code(self) -> str:
        """The production lines with comments and literals blanked; line structure kept."""
        return code_only(self.text())

    def without_comments(self) -> str:
        """The production lines with comments blanked and literals kept."""
        return code_only(self.text(), literals=True)

    def numbered_code(self) -> list[tuple[int, str]]:
        """`(line number, code-only line)` for every production line that has code on it."""
        numbers = [number for number, _ in self.lines]
        return [(number, code) for number, code in zip(numbers, self.code().split("\n"))
                if code.strip()]


def _lines(text: str) -> list[str]:
    """`text` split on `\\n` only, without the empty string after a final newline.

    `code_only` preserves exactly the `\\n` characters, so splitting both the raw text and its
    code-only form this way keeps their line indices aligned.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def production_view(source: str | Path) -> ProductionView:
    """The production view of a Rust source, given its text or its path."""
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    raw = _lines(text)
    code_lines = _lines(code_only(text))
    if _is_test_file(code_lines):
        return ProductionView(())
    kept: list[tuple[int, str]] = []
    i = 0
    while i < len(raw):
        if TEST_ATTR.match(code_lines[i].lstrip()):
            i = _region_end(code_lines, i)
            continue
        kept.append((i + 1, raw[i]))
        i += 1
    return ProductionView(tuple(kept))
