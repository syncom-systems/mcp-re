# SPDX-License-Identifier: Apache-2.0
"""Finding every crate in a repository and the thread spawns in a crate's production code."""

from __future__ import annotations

from bisect import bisect_right
from pathlib import Path

from _owned_worker.config import SPAWN
from _rust_source import SKIP_DIRS, production_view


def _is_crate(directory: Path) -> bool:
    return (directory / "Cargo.toml").is_file() and (directory / "src").is_dir()


def _is_descendable(child: Path) -> bool:
    return child.is_dir() and not child.is_symlink() and child.name not in SKIP_DIRS


def crates(root: Path) -> list[Path]:
    """Every crate directory in the repository, at any depth.

    Depth matters: `sdk/python` and `sdk/typescript` are the native bindings that ship to
    end users, and a depth-1 glob would report a clean tree having read none of them.
    """
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        if _is_crate(current):
            found.append(current)
        stack.extend(child for child in current.iterdir() if _is_descendable(child))
    return sorted(found)


def production_spawns(src: str) -> list[int]:
    """The 1-based line of every `thread::spawn`/`Builder` in real, non-test code.

    Searched in the owner's code-only view, so a `thread::spawn` in a doc comment, a
    string literal or a test region is not a finding, and the line reported is the one
    the spelling sits on in the file.
    """
    view = production_view(src)
    code = view.code()
    starts = [0] + [i + 1 for i, ch in enumerate(code) if ch == "\n"]
    return [view.lines[bisect_right(starts, m.start()) - 1][0] for m in SPAWN.finditer(code)]
