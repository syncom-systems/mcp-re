# SPDX-License-Identifier: Apache-2.0
"""The image definition read as instructions and build arguments."""

from __future__ import annotations

import re


def _skipped(stripped: str, current: str) -> bool:
    """A comment line, or a blank line between instructions."""
    return stripped.startswith("#") or not (current or stripped)


def instructions(text: str) -> list[str]:
    """The definition's instructions, continuation lines joined and comments dropped."""
    out: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if _skipped(stripped, current):
            continue
        current += " " + stripped.removesuffix("\\")
        if not stripped.endswith("\\"):
            out.append(current.strip())
            current = ""
    if current:
        out.append(current.strip())
    return out


def bare(value: str) -> str:
    """A lock digest without its `sha256:` prefix."""
    return value.removeprefix("sha256:")


def build_args(steps: list[str]) -> dict[str, str]:
    """Each `ARG NAME=default` instruction's default, by name."""
    matches = (re.match(r"ARG\s+(\w+)=(\S+)$", step) for step in steps)
    return {m.group(1): m.group(2) for m in matches if m}
