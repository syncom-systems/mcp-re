# SPDX-License-Identifier: Apache-2.0
"""GitHub's path-filter matching."""

from __future__ import annotations

import re

from _workflow.syntax import WorkflowSyntaxError


def _token(pattern: str, i: int) -> tuple[str, int]:
    """The regex for the glob token at `i`, and how many pattern characters it consumed."""
    if pattern.startswith("**/", i):
        return "(?:.*/)?", 3
    if pattern.startswith("**", i):
        return ".*", 2
    if pattern[i] == "*":
        return "[^/]*", 1
    return re.escape(pattern[i]), 1


def _regex(pattern: str) -> str:
    out, i = "", 0
    while i < len(pattern):
        token, width = _token(pattern, i)
        out += token
        i += width
    return out


def glob_matches(pattern: str, path: str) -> bool:
    """GitHub's path-filter semantics: `**` crosses a separator, `*` does not, and `**/`
    also matches no directory at all, so `**/BUILD.bazel` matches the root's.

    `?`, `[...]`, a leading `!` and `+` mean something GitHub-specific that no filter in
    this repository uses; a pattern carrying one is refused rather than matched by a
    guess, because a guess here is a filter read as wider than GitHub applies it.
    """
    if any(ch in pattern for ch in "?[+") or pattern.startswith("!"):
        raise WorkflowSyntaxError(f"path filter {pattern!r} uses syntax this reader does not match")
    return re.fullmatch(_regex(pattern), path) is not None
