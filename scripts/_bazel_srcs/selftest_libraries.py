# SPDX-License-Identifier: Apache-2.0
"""Selftest cases for library `srcs` against the module tree."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import _module_tree
import _rust_targets

from _bazel_srcs.config import TARGET_TABLE
from _bazel_srcs.libraries import check_libraries

LIB = "pub mod alpha;\npub mod beta;\n"
TEST_TARGET_ROW = {
    "kind": "rust_test", "package": "thing", "root": "thing/src/lib.rs",
    "srcs": ["thing/src/lib.rs", "thing/src/alpha.rs", "thing/src/beta.rs"], "testonly": True,
}


@dataclass(frozen=True)
class LibraryCase:
    """One crate fixture and the single finding it must produce, or `None` for "this tree is
    correct and must produce nothing"."""

    name: str
    srcs: list[str]
    files: dict[str, str]
    expect: str | None
    extra_rows: dict | None = None


def _found(case: LibraryCase) -> tuple[list[str], int]:
    library = {"kind": "rust_library", "package": "thing", "root": "thing/src/lib.rs",
               "srcs": [f"thing/{s}" for s in case.srcs], "testonly": False}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _module_tree.materialize_fixture(root, {f"thing/src/{rel}": text for rel, text in case.files.items()})
        (root / TARGET_TABLE).parent.mkdir(parents=True)
        (root / TARGET_TABLE).write_text(
            _rust_targets.fixture({"//thing:thing": library, **(case.extra_rows or {})})
        )
        return check_libraries(root)


def library_case(case: LibraryCase) -> bool:
    """Build a crate and a one-library table, check it, and compare against the expectation."""
    found, checked = _found(case)
    if checked == 0:
        print(f"SELFTEST FAILED [{case.name}]: no library was checked — a vacuous pass")
        return False
    if case.expect is None:
        if found:
            print(f"SELFTEST FAILED [{case.name}]: expected nothing, got {found}")
            return False
        return True
    if len(found) != 1 or case.expect not in found[0]:
        print(f"SELFTEST FAILED [{case.name}]: expected one finding containing "
              f"{case.expect!r}, got {found}")
        return False
    return True


def _fixture_cases() -> list[LibraryCase]:
    """The module tree is the owner's: its one fixture, listed and not. Which files the tree
    reaches — both forms, `#[path]`, inline modules, code only — is `_module_tree`'s selftest.
    What this gate adds is the target's srcs against that tree."""
    fixture = {
        rel[len("src/"):]: text
        for rel, text in _module_tree.FIXTURE.items()
        if rel.startswith("src/") and "mod missing;" not in text
    }
    fixture["lib.rs"] = _module_tree.FIXTURE["src/lib.rs"].replace("mod missing;\n", "")
    reached = sorted(path for path, _ in _module_tree.FIXTURE_TREES["src/lib.rs"].values())
    return [
        LibraryCase("the fixture tree, every reached file listed", reached, fixture, None),
        LibraryCase(
            "the fixture tree, a file reached only through `#[path]` unlisted",
            [p for p in reached if p != "src/elsewhere/sibling.rs"],
            fixture,
            "needs thing/src/elsewhere/sibling.rs",
        ),
        LibraryCase(
            "the fixture tree, the child of an inline module unlisted",
            [p for p in reached if p != "src/outer/nested.rs"],
            fixture,
            "needs thing/src/outer/nested.rs",
        ),
    ]


def _drift_cases() -> list[LibraryCase]:
    plain = {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""}
    return [
        LibraryCase("file module, one missing — the defect that shipped",
                    ["src/lib.rs", "src/alpha.rs"], plain, "mod beta"),
        # The srcs checked are the library row's own: a `rust_test` compiling the library's
        # sources into its own crate answers for nothing in the library.
        LibraryCase("a file in a TEST target's srcs does not satisfy the library's mod",
                    ["src/lib.rs", "src/alpha.rs"], plain, "mod beta",
                    extra_rows={"//thing:thing_test": TEST_TARGET_ROW}),
        LibraryCase("a listed file that does not exist",
                    ["src/lib.rs", "src/alpha.rs", "src/beta.rs", "src/gone.rs"], plain, "does not exist"),
        LibraryCase("a mod that resolves to no file at all",
                    ["src/lib.rs", "src/alpha.rs"],
                    {"lib.rs": "pub mod alpha;\npub mod nowhere;\n", "alpha.rs": ""},
                    "names no file"),
    ]


def _empty_table_case() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / TARGET_TABLE).parent.mkdir(parents=True)
        (root / TARGET_TABLE).write_text(_rust_targets.fixture({}))
        if check_libraries(root)[1] == 0:
            return True
    print("SELFTEST FAILED [an empty table]: it reported libraries checked")
    return False


def library_cases() -> bool:
    results = [library_case(case) for case in _fixture_cases() + _drift_cases()]
    results.append(_empty_table_case())
    return all(results)
