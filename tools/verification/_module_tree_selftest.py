# SPDX-License-Identifier: Apache-2.0
"""The self-test of the module tree: the fixture trees are rustc's, and every property of
declaration reading the gates rely on holds."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _module_tree_decl import declarations, read_declarations
from _module_tree_fixture import FIXTURE_TREES, materialize_fixture
from _module_tree_resolve import declaration_chain, walk


class _Report:
    """The self-test's running tally: each case prints one line and counts a failure."""

    def __init__(self) -> None:
        self.failures = 0

    def case(self, label: str, ok: bool, got: object) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failures += 1
            print(f"        got {got!r}")


def _tree_cases(report: _Report, base: Path) -> None:
    for root, expected in FIXTURE_TREES.items():
        tree = walk(base / root)
        got = {f.module: (f.path.relative_to(base).as_posix(), f.test_only) for f in tree.files}
        report.case(f"the tree of {root} is rustc's", got == expected, got)
    lib = walk(base / "src/lib.rs")
    unresolved = [(p.relative_to(base).as_posix(), d.name) for p, d in lib.unresolved]
    report.case(
        "an unresolved declaration is reported, not dropped",
        unresolved == [("src/lib.rs", "missing")],
        unresolved,
    )


def _declaration_cases(report: _Report, base: Path) -> None:
    names = [d.name for d in read_declarations(base / "src/lib.rs")]
    report.case(
        "a mod in a comment, block comment or raw string declares nothing",
        not {"ghost_line", "ghost_block", "ghost_raw"} & set(names),
        names,
    )
    inline = next(d for d in read_declarations(base / "src/lib.rs") if d.name == "outer")
    report.case(
        "an inline module records where it closes", inline.inline and inline.end_line == 16, inline
    )


def _chain_cases(report: _Report, base: Path) -> None:
    chain = [d.name for d in declaration_chain(base / "src/lib.rs", ("outer", "nested"))]
    report.case(
        "a declaration chain follows an inline module into its file child",
        chain == ["outer", "nested"],
        chain,
    )
    chain = [d.name for d in declaration_chain(base / "src/lib.rs", ("gamma", "sibling", "x"))]
    report.case(
        "a declaration chain follows `#[path]` and stops at a missing segment",
        chain == ["gamma", "sibling"],
        chain,
    )


def _attribute_cases(report: _Report) -> None:
    nested = declarations("#[cfg(test)]\nmod t {\n    mod inner;\n}\n")
    report.case(
        "a declaration inside a test module is test-only",
        [d.cfg_test for d in nested] == [True, True],
        nested,
    )
    attrs = declarations('#[cfg(feature = "x")]\n#[path = "p.rs"]\npub(crate) mod m;\n')
    report.case(
        "every attribute on a declaration is kept, in order",
        attrs[0].attributes == ('#[cfg(feature = "x")]', '#[path = "p.rs"]')
        and attrs[0].path_attribute == "p.rs",
        attrs,
    )
    report.case(
        "an attribute separated from `mod` by another item is not carried",
        declarations("#[cfg(test)]\nfn f() {}\nmod m;\n")[0].attributes == (),
        None,
    )


def selftest() -> int:
    report = _Report()
    with tempfile.TemporaryDirectory() as tmp:
        base = materialize_fixture(Path(tmp))
        _tree_cases(report, base)
        _declaration_cases(report, base)
        _chain_cases(report, base)
        _attribute_cases(report)
    if report.failures:
        print(f"module tree: SELFTEST FAILED ({report.failures})")
        return 1
    print("module tree: selftest passed")
    return 0
