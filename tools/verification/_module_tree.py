# SPDX-License-Identifier: Apache-2.0
"""Rust module-tree resolution — which file each `mod` names, and which files a crate root reaches.

The one owner of the question. Every gate that asks "what does `mod x;` compile" asks it
here, because the answers used to disagree: one walk ignored `#[path]`, one read a `mod`
inside a comment, one resolved a child of an inline `mod a { mod b; }` as a sibling of `a`,
and one treated a crate root named `suite_test.rs` as an ordinary module file. Each gate's
own property was right and each measured a different module tree.

The resolution is rustc's (`rustc_expand::module`), stated as the state a module carries:

  * a module has a directory and, when it was loaded from `name.rs`, a relative offset
    `name` — its children live under `dir/name/`;
  * a crate root, a `mod.rs` and any file loaded through `#[path]` carry no offset, so their
    children live beside them ("mod-rs" files);
  * `mod x;` looks for `dir/[offset/]x.rs`, then `dir/[offset/]x/mod.rs`;
  * `#[path = "p"] mod x;` loads `dir/p` — the offset is NOT applied, which is why
    `#[path]` in `src/a/b.rs` names a file under `src/a/`;
  * an inline `mod z { … }` moves the directory to `dir/[offset/]z` (or `dir/p` under its
    own `#[path]`), so a `mod y;` inside it resolves under `z/`.

Declarations are read from code only: `_rust_source.code_only` blanks comments, string
literals and char literals first, with line structure kept, so a `mod` in a doc comment or
a fixture string declares nothing.

`walk(root)` gives every file a crate root reaches, with its module path, the declaration
that reached it, and whether it is reachable only through a `#[cfg(test)]` declaration.
`FIXTURE` is the one fixture tree the gates' self-tests share.

Run:  python3 tools/verification/_module_tree.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _module_tree_decl import Declaration, declarations, read_declarations  # noqa: E402
from _module_tree_fixture import FIXTURE, FIXTURE_TREES, materialize_fixture  # noqa: E402
from _module_tree_resolve import (  # noqa: E402
    Child,
    ModuleFile,
    Tree,
    children,
    declaration_chain,
    is_mod_rs_name,
    walk,
)
from _module_tree_selftest import selftest  # noqa: E402

__all__ = [
    "FIXTURE",
    "FIXTURE_TREES",
    "REPO_ROOT",
    "Child",
    "Declaration",
    "ModuleFile",
    "Tree",
    "children",
    "declaration_chain",
    "declarations",
    "is_mod_rs_name",
    "materialize_fixture",
    "read_declarations",
    "selftest",
    "walk",
]

if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
