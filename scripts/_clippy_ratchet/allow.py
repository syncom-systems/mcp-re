# SPDX-License-Identifier: Apache-2.0
"""Allow discipline: an exception must be narrow and must name its invariant."""

from __future__ import annotations

import re
from pathlib import Path

from _clippy_ratchet.config import ADOPTED, ALLOW_INNER, ALLOW_OUTER, CONF_EXEMPTION, STRICT_CONF

_NOT_PRODUCTION = {"target", "node_modules", ".git", "tests", "benches", "examples"}


def adopted_in(attr_body: str) -> list[str]:
    return [lint for lint in ADOPTED if f"clippy::{lint}" in attr_body]


def _wide_allow(rel: Path, lineno: int, lints: list[str]) -> list[str]:
    return [
        f"{rel}:{lineno}: `#![allow(clippy::{lint})]` is crate- or "
        f"module-wide. Scope the exception to the item it was granted for; "
        f"a wide allow covers code not yet written and hides it from the "
        f"ratchet."
        for lint in lints
    ]


def _module_allow(rel: Path, lineno: int, lints: list[str]) -> list[str]:
    return [
        f"{rel}:{lineno}: `#[allow(clippy::{lint})]` on a module applies to "
        f"every item inside it, including future ones. Move it to the item "
        f"that needs it."
        for lint in lints
    ]


def _unjustified_allow(rel: Path, lineno: int, lints: list[str]) -> list[str]:
    return [
        f"{rel}:{lineno}: `#[allow(clippy::{lint})]` carries no justification. "
        f"State the invariant that makes the ordinary form safe — name the "
        f"owning type, check or theorem, not merely \"cannot overflow\"."
        for lint in lints
    ]


def _precedes_module(lines: list[str], i: int) -> bool:
    following = lines[i + 1].lstrip() if i + 1 < len(lines) else ""
    return following.startswith(("mod ", "pub mod "))


def _is_justified(lines: list[str], i: int, outer: re.Match[str]) -> bool:
    """A justification is a trailing comment, or a comment line just above."""
    trailing = "//" in lines[i][outer.end():]
    above = i > 0 and lines[i - 1].lstrip().startswith("//")
    return trailing or above


def _line_problems(rel: Path, lines: list[str], i: int) -> list[str]:
    line = lines[i]
    inner = ALLOW_INNER.search(line)
    if inner:
        return _wide_allow(rel, i + 1, adopted_in(inner.group(1)))
    outer = ALLOW_OUTER.search(line)
    if not outer:
        return []
    lints = adopted_in(outer.group(1))
    if not lints:
        return []
    if _precedes_module(lines, i):
        return _module_allow(rel, i + 1, lints)
    if _is_justified(lines, i, outer):
        return []
    return _unjustified_allow(rel, i + 1, lints)


def _file_problems(root: Path, path: Path) -> list[str]:
    rel = path.relative_to(root)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [problem for i in range(len(lines)) for problem in _line_problems(rel, lines, i)]


def _conf_file_problems(root: Path, conf: Path) -> list[str]:
    return [
        f"{conf.relative_to(root)}:{i + 1}: an "
        f"`arithmetic-side-effects-allowed*` type exemption is global and "
        f"unbounded. The C-4 ruling declines it until a genuinely algebraic "
        f"type is found for which the exception is universally true."
        for i, line in enumerate(conf.read_text().splitlines())
        if CONF_EXEMPTION.match(line)
    ]


def _conf_problems(root: Path) -> list[str]:
    out: list[str] = []
    for conf in (root / ".clippy.toml", STRICT_CONF / ".clippy.toml"):
        if conf.exists():
            out += _conf_file_problems(root, conf)
    return out


def allow_discipline(root: Path) -> tuple[list[str], int]:
    """An exception must be narrow and must name its invariant.

    The ratchet counts occurrences, so anything that suppresses the lint over a whole crate
    or module makes the count fall — and a falling count is a legitimate reason to lower the
    baseline. Without this check, `#![allow(clippy::arithmetic_side_effects)]` in a crate
    root is a one-line permanent exemption that the ratchet would report as progress.

    Three rules, from the C-4 ruling:

    - no crate- or module-wide allow of an adopted lint;
    - an item-level allow must carry a justification comment naming the invariant;
    - no `arithmetic-side-effects-allowed*` type exemption in the clippy config, which is
      global and unbounded.
    """
    problems: list[str] = []
    files = 0
    for path in sorted(root.rglob("*.rs")):
        if any(part in _NOT_PRODUCTION for part in path.relative_to(root).parts):
            continue
        files += 1
        problems += _file_problems(root, path)
    return problems + _conf_problems(root), files
