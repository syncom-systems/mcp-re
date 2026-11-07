# SPDX-License-Identifier: Apache-2.0
"""Selftest cases for the guard's hand lists against the module tree: one per way they come apart."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import _module_tree
import _rust_targets

from _bazel_srcs.config import GUARD, TARGET_TABLE
from _bazel_srcs.source_trees import check_source_trees

GUARD_TEMPLATE = (
    'const CRATE_SOURCE_TREES: &[(&str, &str)] = &[\n    ("pkg", "TREE_PKG"),\n{extra}];\n'
    'const NOT_SCANNED: &[(&str, &str)] = &[("skipped", "why")];\n'
    'const CRATE_KINDS: &[&str] = &["rust_library", "rust_binary"];\n'
    'const COMPILED_SOURCE_DIRS: &[&str] = &["src", "examples"];\n'
)
LIBRARY = {"kind": "rust_library", "package": "pkg", "root": "pkg/src/lib.rs", "testonly": False}
DEFAULT_SRCS = 'glob(["src/**/*.rs", "examples/**/*.rs"])'


@dataclass(frozen=True)
class TreeCase:
    """One guard-list scenario and the single finding it must produce, or `None` for none."""

    name: str
    expect: str | None
    extra: str = ""
    rows: dict | None = None
    files: dict[str, str] = field(default_factory=dict)
    srcs: str = DEFAULT_SRCS


def _write_fixture(root: Path, case: TreeCase) -> None:
    fixture = {
        f"pkg/{rel}": text.replace("mod missing;\n", "")
        for rel, text in _module_tree.FIXTURE.items()
        if rel.startswith("src/")
    }
    _module_tree.materialize_fixture(root, {**fixture, **case.files})
    (root / GUARD).parent.mkdir(parents=True)
    (root / GUARD).write_text(GUARD_TEMPLATE.format(extra=case.extra))
    (root / "pkg" / "BUILD.bazel").write_text(
        f'filegroup(\n    name = "guard_src_files",\n    srcs = {case.srcs},\n)\n'
    )
    (root / TARGET_TABLE).parent.mkdir(parents=True)
    (root / TARGET_TABLE).write_text(_rust_targets.fixture(case.rows or {"//pkg:lib": LIBRARY}))


def _as_expected(expect: str | None, found: list[str]) -> bool:
    if expect is None:
        return not found
    return len(found) == 1 and expect in found[0]


def run_case(case: TreeCase) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_fixture(root, case)
        found, checked = check_source_trees(root)
    if checked == 0:
        print(f"SELFTEST FAILED [{case.name}]: no file was checked — a vacuous pass")
        return False
    if not _as_expected(case.expect, found):
        print(f"SELFTEST FAILED [{case.name}]: expected {case.expect!r}, got {found}")
        return False
    return True


def _list_cases() -> list[TreeCase]:
    other = {**LIBRARY, "package": "other", "root": "pkg/src/lib.rs"}
    return [
        TreeCase("the fixture crate, scanned, every file in a walked and globbed directory", None),
        TreeCase("a crate package in neither list", "in neither CRATE_SOURCE_TREES nor NOT_SCANNED",
                 rows={"//pkg:lib": LIBRARY, "//other:lib": other}),
        TreeCase("a hand-listed package that compiles no crate", "compiles no crate",
                 extra='    ("gone", "TREE_GONE"),\n'),
        TreeCase("a `#[path]` module outside the walked directories", "outside the",
                 files={"pkg/src/lib.rs": '#[path = "../shared/x.rs"]\nmod x;\n', "pkg/shared/x.rs": ""}),
    ]


def _glob_cases() -> list[TreeCase]:
    demo = {**LIBRARY, "kind": "rust_binary", "root": "pkg/examples/demo.rs"}
    return [
        TreeCase("an example binary the glob leaves out of the runfiles", "does not glob",
                 rows={"//pkg:lib": LIBRARY, "//pkg:demo": demo},
                 files={"pkg/examples/demo.rs": ""}, srcs='glob(["src/**/*.rs"])'),
        TreeCase("a compiled file the glob's `exclude` leaves out of the runfiles", "does not glob",
                 srcs='glob(\n        ["src/**/*.rs", "examples/**/*.rs"],\n        exclude = ["src/alpha/deep.rs"],\n    )'),
        TreeCase("an `exclude` naming no compiled file excludes nothing", None,
                 srcs='glob(["src/**/*.rs", "examples/**/*.rs"], exclude = ["src/never.rs"])'),
        TreeCase("a `srcs` shape the gate does not read is a finding, not a guess", "does not read",
                 srcs='glob(["src/**/*.rs", "examples/**/*.rs"]) + ["extra.rs"]'),
        TreeCase("a trailing `**` crosses `/`, as Bazel's glob does", None,
                 srcs='glob(["src/**", "examples/**"])'),
        TreeCase("a test-only target's sources are test sources", None,
                 rows={"//pkg:lib": LIBRARY,
                       "//pkg:fixture": {**LIBRARY, "root": "pkg/tests/fixture/lib.rs", "testonly": True}},
                 files={"pkg/tests/fixture/lib.rs": ""}),
    ]


def tree_cases() -> bool:
    return all([run_case(case) for case in _list_cases() + _glob_cases()])
