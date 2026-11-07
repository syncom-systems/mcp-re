# SPDX-License-Identifier: Apache-2.0
"""Line-level rules: which lines a carve-out exempts, and which tokens need no judgement."""

from __future__ import annotations

from _doc_path.config import FENCE, HEADING, SHA_ANCHOR


def _anchored(lines: list[str]) -> list[bool]:
    """Per line: whether its section (from a heading to the next) carries a SHA anchor."""
    anchored = [False] * len(lines)
    start, current = 0, False
    for idx, line in enumerate(lines):
        if HEADING.match(line):
            anchored[start:idx] = [current] * (idx - start)
            start, current = idx, False
        current = current or bool(SHA_ANCHOR.search(line))
    anchored[start:] = [current] * (len(lines) - start)
    return anchored


def fence_langs(lines: list[str]) -> list[str | None]:
    """Per line: the language of the fence it sits inside, or None outside one (and on the
    fence lines themselves)."""
    langs: list[str | None] = []
    current: str | None = None
    for line in lines:
        m = FENCE.match(line)
        if m:
            current = None if current is not None else (m.group(1) or "")
            langs.append(None)
            continue
        langs.append(current)
    return langs


def exempt_lines(lines: list[str]) -> set[int]:
    """Line indices under a carve-out: a `text` fence in a SHA-anchored section.

    A block quoted from a named revision is a record of that revision, so its paths are
    resolved against it and not against this one. The anchor is what distinguishes a
    quotation from a claim; a fence alone is not enough.
    """
    anchored = _anchored(lines)
    return {idx for idx, lang in enumerate(fence_langs(lines)) if lang == "text" and anchored[idx]}


def mechanically_excluded(line: str, start: int, token: str, lang: str | None) -> bool:
    """The five rules that remove a token no judgement is needed on."""
    before = line[start - 1] if start else ""
    if before in ("$", "{", "@"):
        return True
    if token.startswith("HERE/"):
        return True
    if token.startswith("./") and lang == "sh":
        return True
    return token.startswith(("target/", ".verification/", "dist/", "./dist/"))
