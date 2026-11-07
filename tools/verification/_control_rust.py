# SPDX-License-Identifier: Apache-2.0
"""Rust test controls: follow the module tree from each test target's crate root.

The Rust module path is FOLLOWED, never derived from the file path: `_module_tree` says
which file a `mod` names and which inline modules enclose a line, and this module only
reads the test attributes.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import _module_tree
import _rust_targets
from _control_model import Control
from _ecosystems import REPO_ROOT

#: `#[tokio::test]` takes arguments (`flavor = "multi_thread"`, `start_paused = true`), and a
#: test written with them is a test: an attribute matched only in its bare form would leave
#: it outside the census, unclaimed and undispositioned without the gate noticing.
TEST_ATTR = re.compile(r"^(\s*)#\[(?:tokio::)?test(?:\s*\([^\]]*\))?\]")
_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
#: A line that opens an attribute — it may sit between a marker and the item it marks.
ATTR_LINE = re.compile(r"^\s*#\[")


@dataclass
class _Walk:
    """One crate root's walk: the identity its controls take and what it has collected.

    `seen` is per target, not global: the same file reached from two targets is two
    distinct controls, and sharing the set would silently drop the second.
    """

    package: str
    target: str
    seen: set[Path]
    out: list[Control]


def _declared_tests(lines: list[str]) -> Iterator[tuple[int, int, str]]:
    """`(attribute line, fn line, fn name)` for each `#[test]` followed by its function.

    Other attributes and blank lines may sit between the two; anything else means the
    attribute did not introduce a function.
    """
    attribute_line: int | None = None
    for number, line in enumerate(lines, start=1):
        if TEST_ATTR.match(line):
            attribute_line = number
            continue
        if attribute_line is None:
            continue
        fn = _FN.match(line)
        if fn:
            yield attribute_line, number, fn.group(1)
            attribute_line = None
        elif not (ATTR_LINE.match(line) or not line.strip()):
            attribute_line = None


def _enclosing_modules(inline: list, line: int) -> tuple[str, ...]:
    """The inline module path around `line`, innermost declaration first-matched."""
    for declaration in sorted(inline, key=lambda d: len(d.enclosing), reverse=True):
        if declaration.line < line <= declaration.end_line:
            return tuple(name for name, _ in declaration.enclosing) + (declaration.name,)
    return ()


def _tests_in(walk: _Walk, path: Path, lines: list[str], prefix: tuple[str, ...]) -> list[Control]:
    inline = [d for d in _module_tree.read_declarations(path) if d.inline]
    # Normalized: a `#[path = "../x/mod.rs"]` module is reached through `..`, and the file
    # is one carrier however it is reached.
    carrier = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    return [
        Control(
            project=walk.package,
            identity=f"{walk.target}#{'::'.join(prefix + _enclosing_modules(inline, attribute_line) + (name,))}",
            kind="rust-test",
            carrier=carrier,
            line=number,
        )
        for attribute_line, number, name in _declared_tests(lines)
    ]


def _walk_rust_file(walk: _Walk, path: Path, mod_rs: bool, prefix: tuple[str, ...]) -> None:
    """Collect every `#[test]` reachable from `path`, and recurse into its file modules."""
    key = path.resolve()
    if key in walk.seen:
        return
    walk.seen.add(key)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return
    walk.out.extend(_tests_in(walk, path, lines, prefix))
    for child in _module_tree.children(path, mod_rs=mod_rs):
        if child.file is None:
            continue
        inner = tuple(name for name, _ in child.declaration.enclosing)
        _walk_rust_file(walk, child.file, child.mod_rs, prefix + inner + (child.declaration.name,))


def rust_controls() -> list[Control]:
    """Every `#[test]` / `#[tokio::test]` reachable from a crate root some test target compiles.

    The roots come from the build graph (`_rust_targets`), not from a directory
    convention: a root no `rust_test` compiles holds no test anything runs, and a module
    only a binary declares is reached through that binary's root.
    """
    out: list[Control] = []
    for root, entry in sorted(_rust_targets.crate_roots().items()):
        if "rust_test" not in entry["kinds"]:
            continue
        identity = _rust_targets.root_identity(root, entry["package"])
        _walk_rust_file(_Walk(entry["package"], identity, set(), out), REPO_ROOT / root, True, ())
    return out
