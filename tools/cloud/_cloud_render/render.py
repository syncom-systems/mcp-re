# SPDX-License-Identifier: Apache-2.0
"""Substituting `@@NAME@@` placeholders, and refusing what the result must never contain."""

from __future__ import annotations

import re

from _cloud_render.check import Refused, check_value

PLACEHOLDER = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
OPEN_WORLD = re.compile(r"(?<![\d.])0\.0\.0\.0/0\b|(?<![\w:])::/0\b")


def _without_comments(text: str) -> str:
    """YAML/shell-style comment lines and trailing ` # …` dropped; JSON has none."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s#\s.*$", "", line))
    return "\n".join(out)


def _substitute(values: dict[str, str]):
    def substitute(match: re.Match) -> str:
        name = match.group(1)
        if name not in values:
            return match.group(0)
        return '", "'.join(values[name].split(",")) if name.endswith("_CIDRS") else values[name]

    return substitute


def _refuse_unused(template: str, values: dict[str, str]) -> None:
    unused = sorted(set(values) - set(PLACEHOLDER.findall(template)))
    if unused:
        raise Refused(f"value(s) for placeholder(s) the template does not have: {', '.join(unused)}")


def _refuse_unresolved(rendered: str) -> None:
    left = sorted(set(PLACEHOLDER.findall(rendered)))
    if left:
        raise Refused(f"unresolved placeholder(s): {', '.join(left)}")


def _refuse_open_world(rendered: str) -> None:
    if OPEN_WORLD.search(_without_comments(rendered)):
        raise Refused("the rendered configuration opens a network to the whole internet (0.0.0.0/0 or ::/0)")


def render(template: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        check_value(name, value)
    _refuse_unused(template, values)
    out = PLACEHOLDER.sub(_substitute(values), template)
    _refuse_unresolved(out)
    _refuse_open_world(out)
    return out
