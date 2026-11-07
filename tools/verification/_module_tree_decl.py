# SPDX-License-Identifier: Apache-2.0
"""Reading `mod` declarations out of Rust source: one `Declaration` per `mod`, read from code
only (comments, string and char literals blanked, line structure kept), with the attributes it
carries and the inline modules it sits inside."""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, replace
from pathlib import Path

from _rust_source import TEST_ATTR, code_only

#: A module declaration in code-only text: optional visibility, `mod`, the name, then `;`
#: (a file module) or `{` (an inline one).
_DECL = re.compile(
    r"(?<![A-Za-z0-9_])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*([;{])"
)
_TOKENS = re.compile(r"#!?\[|[{};]")
_PATH_ATTR = re.compile(r'^#\[\s*path\s*=\s*"([^"]*)"\s*\]$', re.S)


@dataclass(frozen=True)
class Declaration:
    """One `mod` declaration in one file."""

    name: str
    #: 1-based line of the `mod` keyword.
    line: int
    #: `mod x { … }` rather than `mod x;`.
    inline: bool
    #: The outer attributes written on the declaration, as code text (`#[cfg(test)]`, …).
    attributes: tuple[str, ...]
    #: The inline modules the declaration sits inside, outermost first, as
    #: `(name, path attribute or None)`.
    enclosing: tuple[tuple[str, str | None], ...]
    #: For an inline module, the 1-based line of its closing brace; 0 otherwise.
    end_line: int = 0
    #: Whether an enclosing inline module is `#[cfg(test)]`.
    in_test_region: bool = False

    @property
    def path_attribute(self) -> str | None:
        for attribute in self.attributes:
            match = _PATH_ATTR.match(attribute)
            if match:
                return match.group(1)
        return None

    @property
    def cfg_test(self) -> bool:
        """Compiled only under test: its own attribute, or an enclosing test module's."""
        return self.in_test_region or any(TEST_ATTR.match(a) for a in self.attributes)



def _attribute_end(code: str, start: int) -> int:
    depth = 0
    for j in range(start, len(code)):
        depth += (code[j] == "[") - (code[j] == "]")
        if code[j] == "]" and depth == 0:
            return j + 1
    return len(code)


def _declaration_first(decl: re.Match[str] | None, token: re.Match[str] | None) -> bool:
    """Whether the next thing in the source is the declaration rather than a token."""
    return decl is not None and (token is None or decl.start() <= token.start())


class _Scanner:
    """One pass over a source's code: declarations, the attributes before them and the braces
    around them, in token order."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.code = code_only(text)
        self.line_starts = [0] + [i + 1 for i, ch in enumerate(self.code) if ch == "\n"]
        self.out: list[Declaration] = []
        #: (start, text) of each outer attribute, keyed by the offset it ends at, for reading
        #: those a declaration carries.
        self.attributes: dict[int, tuple[int, str]] = {}
        #: Open braces: the inline module each one opened (an index into `out`), or None.
        self.braces: list[int | None] = []
        self.pos = 0

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.line_starts)
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid
        return lo + 1

    def _refreshed(self, decl: re.Match[str] | None) -> re.Match[str] | None:
        """`decl`, searched for again once `pos` has passed its start."""
        if decl is not None and decl.start() < self.pos:
            return _DECL.search(self.code, self.pos)
        return decl

    def run(self) -> list[Declaration]:
        # The first declaration at or after `pos` stays the first one until `pos` passes its
        # start, so it is searched for again only then; searching on every token re-scanned
        # the rest of the file once per token.
        decl = _DECL.search(self.code, self.pos)
        while True:
            decl = self._refreshed(decl)
            token = _TOKENS.search(self.code, self.pos)
            if token is None and decl is None:
                return self.out
            if _declaration_first(decl, token):
                self._declare(decl)
            else:
                assert token is not None
                self._token(token)

    def _skip_space_back(self, offset: int) -> int:
        while offset and self.code[offset - 1].isspace():
            offset -= 1
        return offset

    def _carried_attributes(self, start: int) -> list[str]:
        carried: list[str] = []
        while True:
            attribute = self.attributes.get(self._skip_space_back(start))
            if attribute is None:
                return carried
            carried.insert(0, attribute[1])
            start = attribute[0]

    def _declare(self, decl: re.Match[str]) -> None:
        enclosing_idx = [b for b in self.braces if b is not None]
        enclosing = tuple((self.out[b].name, self.out[b].path_attribute) for b in enclosing_idx)
        inline = decl.group(2) == "{"
        self.out.append(
            Declaration(
                name=decl.group(1),
                line=self.line_of(decl.start()),
                inline=inline,
                attributes=tuple(self._carried_attributes(decl.start())),
                enclosing=enclosing,
                in_test_region=any(self.out[b].cfg_test for b in enclosing_idx),
            )
        )
        if inline:
            self.braces.append(len(self.out) - 1)
        self.pos = decl.end()

    def _close_brace(self, token: re.Match[str]) -> None:
        if not self.braces:
            return
        opened = self.braces.pop()
        if opened is not None:
            self.out[opened] = replace(self.out[opened], end_line=self.line_of(token.start()))

    def _token(self, token: re.Match[str]) -> None:
        lexeme = token.group(0)
        self.pos = token.end()
        if lexeme.startswith("#"):
            end = _attribute_end(self.code, token.start() + len(lexeme) - 1)
            if lexeme == "#[":
                # From the source, not the blanked code: `#[path = "…"]` is a string.
                self.attributes[end] = (
                    token.start(),
                    " ".join(self.text[token.start() : end].split()),
                )
            self.pos = end
        elif lexeme == "{":
            self.braces.append(None)
        elif lexeme == "}":
            self._close_brace(token)


def declarations(text: str) -> list[Declaration]:
    """Every `mod` declaration in a Rust source, in source order, from code only."""
    return _Scanner(text).run()


def read_declarations(path: Path) -> list[Declaration]:
    """`declarations` of a file, parsed once per version of the file."""
    stat = path.stat()
    return list(_cached_declarations(path.resolve(), stat.st_mtime_ns, stat.st_size))


@functools.lru_cache(maxsize=4096)
def _cached_declarations(path: Path, _mtime_ns: int, _size: int) -> tuple[Declaration, ...]:
    return tuple(declarations(path.read_text(encoding="utf-8", errors="replace")))
