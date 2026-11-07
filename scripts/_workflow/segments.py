# SPDX-License-Identifier: Apache-2.0
"""Splitting a shell command into the simple commands it runs."""

from __future__ import annotations


def _substitution_end(text: str, start: int, close: str) -> int:
    """The index after the substitution body that starts at `start` and ends at `close`.

    `$(` nests, so a `$(` inside a `$(...)` opens a level of its own.
    """
    depth, j = 1, start
    while j < len(text) and depth:
        if close == ")" and text.startswith("$(", j):
            depth += 1
            j += 1
        elif text[j] == close:
            depth -= 1
        j += 1
    return j


class _Splitter:
    def __init__(self, text: str) -> None:
        self.text = text
        self.out: list[str] = []
        self.current: list[str] = []
        self.quote = ""
        self.i = 0

    def run(self) -> list[str]:
        while self.i < len(self.text):
            self._step()
        self._cut()
        return [segment.strip() for segment in self.out if segment.strip()]

    def _cut(self) -> None:
        self.out.append("".join(self.current))
        self.current = []

    def _take(self, ch: str) -> None:
        self.current.append(ch)
        self.i += 1

    def _step(self) -> None:
        ch = self.text[self.i]
        if self.quote == "'":
            self._single_quoted(ch)
        elif self.text.startswith("$(", self.i) or ch == "`":
            self._substitution(ch)
        elif self.quote == '"':
            self._double_quoted(ch)
        elif ch in "'\"":
            self.quote = ch
            self._take(ch)
        elif width := self._separator_width(ch):
            self._cut()
            self.i += width
        else:
            self._take(ch)

    def _separator_width(self, ch: str) -> int:
        """How many characters the command separator at the cursor takes; 0 when none starts."""
        if self.text.startswith(("&&", "||"), self.i):
            return 2
        return 1 if ch in ";|" else 0

    def _single_quoted(self, ch: str) -> None:
        if ch == "'":
            self.quote = ""
        self._take(ch)

    def _double_quoted(self, ch: str) -> None:
        if ch == '"':
            self.quote = ""
        self._take(ch)

    def _substitution(self, ch: str) -> None:
        """Lift a `$(...)` or backtick pair out as commands of its own."""
        close, start = (")", self.i + 2) if ch == "$" else ("`", self.i + 1)
        end = _substitution_end(self.text, start, close)
        inner = self.text[start : end - 1]
        if not inner.lstrip().startswith("#"):
            self.out.extend(segments(inner))
        self.current.append(" ")
        self.i = end


def segments(text: str) -> list[str]:
    """The simple commands in `text`: split at `&&`, `||`, `;` and `|` outside quotes, with
    every command substitution — `$(...)` or a backtick pair — lifted out as commands of its
    own, because what it runs is run.

    A backtick pair whose content starts with `#` is a comment that expands to nothing,
    which is how a long `&&` chain carries prose between its links.
    """
    return _Splitter(text).run()
