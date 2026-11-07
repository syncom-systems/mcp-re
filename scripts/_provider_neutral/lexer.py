# SPDX-License-Identifier: Apache-2.0
"""Quote-aware splitting of one shell line into command segments, and the command word of a segment."""

from __future__ import annotations

from _provider_neutral.config import ASSIGNMENT, PREFIX_WORDS

_SEPARATOR_CHARS = ";|(){}`"


def _separator_width(line: str, i: int) -> int:
    """How many characters of an unquoted separator start at `i`: 0 when none does."""
    if line.startswith(("&&", "||", "$("), i):
        return 2
    return 1 if line[i] in _SEPARATOR_CHARS else 0


def _depth_delta(ch: str, close: str) -> int:
    if close == ")" and ch == "(":
        return 1
    return -1 if ch == close else 0


def _after_substitution(line: str, start: int, close: str) -> int:
    """Index just past the `close` that ends a substitution whose body starts at `start`."""
    depth, k = 1, start
    while k < len(line) and depth:
        depth += _depth_delta(line[k], close)
        k += 1
    return k


class _Lexer:
    """Walks a line once, collecting words into segments and the substitutions found in
    double quotes into `nested` (code of their own, split afterwards)."""

    def __init__(self, line: str) -> None:
        self.line = line
        self.i = 0
        self.segments: list[list[str]] = [[]]
        self.word: list[str] = []
        self.nested: list[str] = []

    def run(self) -> None:
        while self.i < len(self.line):
            self._step(self.line[self.i])
        self._end_word()

    def _end_word(self) -> None:
        if self.word:
            self.segments[-1].append("".join(self.word))
            self.word.clear()

    def _end_segment(self) -> None:
        self._end_word()
        self.segments.append([])

    def _step(self, c: str) -> None:
        if c == "'":
            self._single_quoted()
        elif c == '"':
            self._double_quoted()
        else:
            self._unquoted(c)

    def _single_quoted(self) -> None:
        end = self.line.find("'", self.i + 1)
        end = len(self.line) if end < 0 else end
        self.word.append(self.line[self.i + 1:end])
        self.i = end + 1

    def _double_quoted(self) -> None:
        j = self.i + 1
        while j < len(self.line) and self.line[j] != '"':
            j = self._inside_double(j)
        self.word.append(self.line[self.i + 1:j])
        self.i = j + 1

    def _inside_double(self, j: int) -> int:
        """The index after one step of a double-quoted string: an escape, a substitution or a character."""
        if self.line[j] == "\\":
            return j + 2
        if self.line.startswith("$(", j) or self.line[j] == "`":
            return self._substitution(j)
        return j + 1

    def _substitution(self, j: int) -> int:
        close = ")" if self.line[j] == "$" else "`"
        start = j + (2 if close == ")" else 1)
        end = _after_substitution(self.line, start, close)
        self.nested.append(self.line[start:end - 1])
        return end

    def _unquoted(self, c: str) -> None:
        width = _separator_width(self.line, self.i)
        if width:
            self._end_segment()
            self.i += width
            return
        if c.isspace():
            self._end_word()
        else:
            self.word.append(c)
        self.i += 1


def segments(line: str) -> list[list[str]]:
    """Command segments of one shell line, as word lists, quote-aware.

    A single-quoted string is one opaque word. A double-quoted string is one word too,
    except that a `$( … )` or backtick substitution inside it is code and is split into
    segments of its own — `X="$(gcloud config get-value project)"` is a gcloud invocation.
    Unquoted `&& || ; | ( ) { } $(` and backticks end a segment.
    """
    lexer = _Lexer(line)
    lexer.run()
    out = [seg for seg in lexer.segments if seg]
    for inner in lexer.nested:
        out.extend(segments(inner))
    return out


def _prefix_width(words: list[str], i: int) -> int:
    """How many words a prefix at `i` occupies; 0 when `words[i]` is the command itself."""
    word = words[i]
    if ASSIGNMENT.match(word) or word in PREFIX_WORDS:
        return 1
    if word == "timeout" and i + 1 < len(words):
        return 2
    return 0


def command_word(words: list[str]) -> tuple[str | None, list[str]]:
    i = 0
    while i < len(words):
        width = _prefix_width(words, i)
        if not width:
            return words[i], words[i + 1:]
        i += width
    return None, []
