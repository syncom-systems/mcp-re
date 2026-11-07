# SPDX-License-Identifier: Apache-2.0
"""Cargo invocations in shell-like text: scripts, fenced blocks of command documents, package.json scripts."""

from __future__ import annotations

import json
import re

from _no_cargo.config import CARGO_BIN, FENCE, INLINE, PRINTS, SHELL_LANGS, SHELL_RULES, Hit


def is_cargo_word(text: str) -> bool:
    word = text.strip().rsplit("/", 1)[-1]
    return bool(re.fullmatch(CARGO_BIN, word))


def _live_line(raw: str) -> str:
    """The part of a line that runs: nothing for a comment, the text before ` #` otherwise."""
    if raw.lstrip().startswith("#"):
        return ""
    return raw.split(" #", 1)[0]


def _first_rule(line: str) -> str | None:
    return next((rule for rule, pattern in SHELL_RULES if pattern.search(line)), None)


def shell_hits(text: str) -> list[Hit]:
    """(line, rule, text) for every Cargo invocation in shell-like text."""
    out: list[Hit] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _live_line(raw)
        if not line.strip() or PRINTS.match(line):
            continue
        rule = _first_rule(line)
        if rule is not None:
            out.append((number, rule, raw.strip()))
    return out


class _Block:
    """An open fenced block: where it starts, its language, and the lines read so far."""

    def __init__(self, start: int, lang: str) -> None:
        self.start = start
        self.lang = lang
        self.lines: list[str] = []

    def hits(self) -> list[Hit]:
        if self.lang not in SHELL_LANGS:
            return []
        body = "\n".join(line.lstrip("$ ").rstrip() for line in self.lines)
        return [(self.start + n, rule, text) for n, rule, text in shell_hits(body)]


def _inline_hits(number: int, line: str) -> list[Hit]:
    # A lone word names a thing — a job id, a binary — rather than running it.
    return [
        (number, "inline command", span)
        for span in INLINE.findall(line)
        if " " in span.strip() and shell_hits(span)
    ]


class _MarkdownScan:
    """Reads a command document a line at a time, inside or outside a fenced block."""

    def __init__(self) -> None:
        self.block: _Block | None = None
        self.out: list[Hit] = []

    def feed(self, number: int, line: str) -> None:
        fence = FENCE.match(line)
        if self.block is not None:
            self._inside(self.block, fence, line)
        elif fence:
            self.block = _Block(number, fence.group(2).lower())
        else:
            self.out += _inline_hits(number, line)

    def _inside(self, block: _Block, fence: re.Match[str] | None, line: str) -> None:
        if fence:
            self.out += block.hits()
            self.block = None
        else:
            block.lines.append(line)


def markdown_hits(text: str) -> list[Hit]:
    """Invocations in a maintained command document: its fenced shell blocks, and inline
    code spans that are a command — "run `cargo clippy`" instructs whoever reads it."""
    scan = _MarkdownScan()
    for number, line in enumerate(text.splitlines(), start=1):
        scan.feed(number, line)
    return scan.out


def package_json_hits(text: str) -> list[Hit]:
    try:
        scripts = json.loads(text).get("scripts", {})
    except (json.JSONDecodeError, AttributeError):
        return []
    return [(0, f"package script `{name}`", body) for name, body in scripts.items()
            if shell_hits(body)]
