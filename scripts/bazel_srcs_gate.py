#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bazel srcs gate — every file a library's module tree reaches is in its `srcs`.

`mcp-re-proxy` hand-lists its library sources (`_PROXY_LIB_SRCS`) because three library
flavors share the list, and a hand-list drifts: `src/audit_sink.rs` landed with the
ADR-MCPS-035 audit surface and was never added, so cargo built a module Bazel could not
find and every Bazel target downstream of the proxy library failed with E0583.

The semantic-drift gate compares TARGETS, not sources, so it passed. The only thing that
caught this was a full `bazel test //...` — 30+ minutes, and per its own commit message it
"had never once completed during this audit", which is exactly how the miss survived
several rounds of review.

This is that check at one second. The build graph's `srcs` for every library target come
from the committed target table, `verification/generated/rust-targets.json`, which
`tools/verification/rust-targets --check` holds to `bazel query`. The gate walks each
library's module tree from its crate root and requires that each reached file is in that
target's `srcs`, and that each listed file exists. A glob cannot drift, so a globbing
library passes by construction; checking it costs nothing and needs no exemption rule.

Two properties are load-bearing, because each one had a silent-blindness failure mode:

- **The `srcs` are the LIBRARY target's.** A test target compiling the library's sources,
  or a `data` glob over `src/`, satisfies nothing: the table row is the library's own.
- **The module tree is rustc's.** `tools/verification/_module_tree.py` owns it: both
  file forms, `#[path]`, inline modules, and declarations read from code only. A walk
  that stops at a resolved file observes nothing after the first file-to-directory
  split, which is precisely when a hand-list starts to drift.

The second hand list is the audit-vocabulary guard's: `CRATE_SOURCE_TREES` names the
crate packages it scans, `COMPILED_SOURCE_DIRS` the directories it walks in each, and each
package's `guard_src_files` glob the files its runfiles carry. A crate package missing from
the list, a file a crate target reaches outside those directories, or one the glob leaves
out of the runfiles, is a file the guard never reads while it reports a clean scan. Each is
checked against the module tree of every crate target the build graph compiles. The
`guard_src_files` filegroup is not a Rust target, so its glob is read from `BUILD.bazel`
and matched with `workflow_reader.glob_matches`, where `**` crosses `/` as Bazel's does.

Run:  python3 scripts/bazel_srcs_gate.py
      python3 scripts/bazel_srcs_gate.py --selftest
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))
sys.path.insert(0, str(REPO / "scripts"))

import _module_tree  # noqa: E402
from workflow_reader import glob_matches  # noqa: E402

def balanced(text: str, start: int, opener: str, closer: str) -> str:
    """The text from `start` (at `opener`) through its matching `closer`, inclusive."""
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def attribute_value(text: str, start: int) -> str:
    """The text of one Starlark attribute value beginning at `start`.

    Delimiter-balanced, so a value spanning several lines — `glob([...]) + [...]` — is read
    whole and the next attribute is not read at all.
    """
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[start:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return text[start:i]
    return text[start:]


def check_library(root: Path, label: str, row: dict) -> list[str]:
    """Findings for one library target: every file its module tree reaches is in its
    `srcs`, every listed file exists, and every declaration resolves.

    The tree is walked to the bottom even under an unlisted file: one run names every
    missing entry, not one per re-run.
    """
    listed = set(row["srcs"])
    findings: list[str] = []
    tree = _module_tree.walk(root / row["root"])
    for module in tree.files:
        rel = module.path.relative_to(root).as_posix()
        if rel not in listed:
            declared = module.declared_by.relative_to(root).as_posix() if module.declared_by else "?"
            findings.append(
                f"{label}: `mod {module.module[-1]};` in {declared} needs {rel} in the target's "
                f"srcs — rustc compiles it, Bazel cannot find it (E0583). If BUILD.bazel already "
                f"lists it, regenerate the table: `tools/verification/rust-targets --write`"
            )
    for declaring, decl in tree.unresolved:
        findings.append(
            f"{label}: `mod {decl.name};` in {declaring.relative_to(root).as_posix()} "
            f"names no file — rustc cannot compile it either"
        )
    for entry in sorted(listed):
        if not (root / entry).is_file():
            findings.append(f"{label}: lists {entry}, which does not exist")
    return findings


def check_libraries(root: Path) -> tuple[list[str], int]:
    """Every library target in the table against its module tree. Returns the findings and
    how many libraries were checked."""
    rows = json.loads((root / TARGET_TABLE).read_text(encoding="utf-8"))["targets"]
    findings: list[str] = []
    libraries = sorted(label for label, row in rows.items() if row["kind"] == "rust_library")
    for label in libraries:
        findings.extend(check_library(root, label, rows[label]))
    return findings, len(libraries)


GUARD = Path("mcp-re-conformance") / "tests" / "audit_vocabulary_guard_test.rs"
TARGET_TABLE = Path("verification") / "generated" / "rust-targets.json"


def _rust_slice_const(text: str, name: str) -> str:
    """The body of `const NAME: &[…] = &[ … ];` in a Rust source."""
    match = re.search(r"\bconst\s+" + name + r"\s*:[^=]*=\s*&\[", text)
    if match is None:
        raise SystemExit(f"bazel srcs gate: {GUARD} declares no `{name}` — the hand list moved")
    return balanced(text, match.end() - 1, "[", "]")


def _first_strings(body: str) -> list[str]:
    """The first string of every tuple in a slice of tuples."""
    return re.findall(r'\(\s*"([^"]+)"\s*,', body)


def _guard_patterns(build_text: str) -> tuple[list[str], list[str]]:
    """The include and exclude patterns of a package's `guard_src_files` glob, or none.

    Only `srcs = glob([...])`, with or without `exclude = [...]`, is read. Any other `srcs`
    shape raises `ValueError`: a pattern read from the wrong list would mark an excluded file
    as carried.
    """
    match = re.search(r'name\s*=\s*"guard_src_files"', build_text)
    if match is None:
        return [], []
    rule = balanced(build_text, build_text.rfind("(", 0, match.start()), "(", ")")
    srcs = re.search(r"\bsrcs\s*=\s*", rule)
    value = attribute_value(rule, srcs.end()).strip() if srcs else ""
    if not value.startswith("glob(") or balanced(value, value.index("("), "(", ")") != value[4:]:
        raise ValueError(f"guard_src_files srcs this gate does not read: {value!r}")
    call = value[5:-1]
    include = balanced(call, call.index("["), "[", "]")
    rest = call[call.index("[") + len(include) :]
    exclude_at = re.search(r"\bexclude\s*=\s*\[", rest)
    exclude = balanced(rest, exclude_at.end() - 1, "[", "]") if exclude_at else "[]"
    if re.sub(r"\bexclude\s*=\s*\[[^\]]*\]", "", rest).strip(" ,\n") != "":
        raise ValueError(f"guard_src_files glob arguments this gate does not read: {value!r}")
    return re.findall(r'"([^"]+)"', include), re.findall(r'"([^"]+)"', exclude)


def check_source_trees(root: Path) -> tuple[list[str], int]:
    """The audit-vocabulary guard's hand lists against the module trees of the crate
    targets the build graph compiles. Returns the findings and how many files were checked.
    """
    guard = (root / GUARD).read_text(encoding="utf-8")
    scanned = set(_first_strings(_rust_slice_const(guard, "CRATE_SOURCE_TREES")))
    not_scanned = set(_first_strings(_rust_slice_const(guard, "NOT_SCANNED")))
    kinds = set(re.findall(r'"([^"]+)"', _rust_slice_const(guard, "CRATE_KINDS")))
    dirs = re.findall(r'"([^"]+)"', _rust_slice_const(guard, "COMPILED_SOURCE_DIRS"))
    rows = json.loads((root / TARGET_TABLE).read_text(encoding="utf-8"))["targets"]

    findings: list[str] = []
    crate_packages = {row["package"] for row in rows.values() if row["kind"] in kinds}
    for package in sorted(crate_packages - scanned - not_scanned):
        findings.append(
            f"{GUARD}: crate package {package} is in neither CRATE_SOURCE_TREES nor NOT_SCANNED "
            f"— the guard scans it by nobody"
        )
    for package in sorted(scanned - crate_packages):
        findings.append(f"{GUARD}: CRATE_SOURCE_TREES names {package}, which compiles no crate")

    checked = 0
    base = root.resolve()
    #: Each package's `(include, exclude)` glob patterns, or `None` when its `srcs` is unread.
    globs: dict[str, tuple[list[str], list[str]] | None] = {}
    for label, row in sorted(rows.items()):
        package = row["package"]
        # A test-only target is linked by tests alone — Bazel refuses any other consumer — so
        # its sources are test sources, which the guard does not scan by design.
        if row["kind"] not in kinds or package not in scanned or row["testonly"]:
            continue
        if package not in globs:
            build = root / package / "BUILD.bazel"
            try:
                globs[package] = _guard_patterns(build.read_text(encoding="utf-8")) if build.is_file() else ([], [])
            except ValueError as exc:
                findings.append(f"{package}/BUILD.bazel: {exc}")
                globs[package] = None
        read = globs[package]
        for module in _module_tree.walk(root / row["root"]).files:
            rel = os.path.relpath(module.path.resolve(), base)
            within = rel[len(package) + 1 :] if rel.startswith(f"{package}/") else None
            checked += 1
            if within is None or not any(within.startswith(f"{d}/") for d in dirs):
                findings.append(
                    f"{label} compiles {rel}, outside the {dirs} the audit-vocabulary guard "
                    f"walks in {package} — the guard never reads it"
                )
            elif read is not None and (
                not any(glob_matches(p, within) for p in read[0])
                or any(glob_matches(p, within) for p in read[1])
            ):
                findings.append(
                    f"{label} compiles {rel}, which {package}:guard_src_files does not glob — "
                    f"the guard's runfiles do not carry it"
                )
    return findings, checked


def selftest() -> int:
    def case(name: str, srcs: list[str], files: dict[str, str], expect: str | None,
             extra_rows: dict | None = None) -> bool:
        """Build a crate and a one-library table, check it, and compare against one
        expected finding: `expect` is a substring the single finding must contain, or None
        for "this tree is correct and must produce nothing"."""
        library = {"kind": "rust_library", "package": "thing", "root": "thing/src/lib.rs",
                   "srcs": [f"thing/{s}" for s in srcs], "testonly": False}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _module_tree.materialize_fixture(root, {f"thing/src/{rel}": text for rel, text in files.items()})
            (root / TARGET_TABLE).parent.mkdir(parents=True)
            (root / TARGET_TABLE).write_text(
                json.dumps({"targets": {"//thing:thing": library, **(extra_rows or {})}})
            )
            found, checked = check_libraries(root)
        if checked == 0:
            print(f"SELFTEST FAILED [{name}]: no library was checked — a vacuous pass")
            return False
        if expect is None:
            if found:
                print(f"SELFTEST FAILED [{name}]: expected nothing, got {found}")
                return False
            return True
        if len(found) != 1 or expect not in found[0]:
            print(f"SELFTEST FAILED [{name}]: expected one finding containing "
                  f"{expect!r}, got {found}")
            return False
        return True

    LIB = "pub mod alpha;\npub mod beta;\n"
    ok = True

    # --- the module tree is the owner's: its one fixture, listed and not ----------
    # Which files the tree reaches — both forms, `#[path]`, inline modules, code only — is
    # `_module_tree`'s selftest. What this gate adds is the target's srcs against that tree.
    fixture = {
        rel[len("src/"):]: text
        for rel, text in _module_tree.FIXTURE.items()
        if rel.startswith("src/") and "mod missing;" not in text
    }
    fixture["lib.rs"] = _module_tree.FIXTURE["src/lib.rs"].replace("mod missing;\n", "")
    reached = sorted(path for path, _ in _module_tree.FIXTURE_TREES["src/lib.rs"].values())
    ok &= case("the fixture tree, every reached file listed", reached, fixture, None)
    ok &= case(
        "the fixture tree, a file reached only through `#[path]` unlisted",
        [p for p in reached if p != "src/elsewhere/sibling.rs"],
        fixture,
        "needs thing/src/elsewhere/sibling.rs",
    )
    ok &= case(
        "the fixture tree, the child of an inline module unlisted",
        [p for p in reached if p != "src/outer/nested.rs"],
        fixture,
        "needs thing/src/outer/nested.rs",
    )
    ok &= case(
        "file module, one missing — the defect that shipped",
        ["src/lib.rs", "src/alpha.rs"],
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a file in a TEST target's srcs does not satisfy the library's mod",
        # The srcs checked are the library row's own: a `rust_test` compiling the library's
        # sources into its own crate answers for nothing in the library.
        ["src/lib.rs", "src/alpha.rs"],
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
        extra_rows={"//thing:thing_test": {
            "kind": "rust_test", "package": "thing", "root": "thing/src/lib.rs",
            "srcs": ["thing/src/lib.rs", "thing/src/alpha.rs", "thing/src/beta.rs"], "testonly": True}},
    )
    ok &= case(
        "a listed file that does not exist",
        ["src/lib.rs", "src/alpha.rs", "src/beta.rs", "src/gone.rs"],
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "does not exist",
    )
    ok &= case(
        "a mod that resolves to no file at all",
        ["src/lib.rs", "src/alpha.rs"],
        {"lib.rs": "pub mod alpha;\npub mod nowhere;\n", "alpha.rs": ""},
        "names no file",
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / TARGET_TABLE).parent.mkdir(parents=True)
        (root / TARGET_TABLE).write_text(json.dumps({"targets": {}}))
        if check_libraries(root)[1] != 0:
            print("SELFTEST FAILED [an empty table]: it reported libraries checked")
            ok = False

    ok &= _selftest_source_trees()

    if not ok:
        return 1
    print("bazel srcs gate selftest: PASS")
    return 0


def _selftest_source_trees() -> bool:
    """The guard's hand lists against the module tree: one case per way they come apart."""
    guard = (
        'const CRATE_SOURCE_TREES: &[(&str, &str)] = &[\n    ("pkg", "TREE_PKG"),\n{extra}];\n'
        'const NOT_SCANNED: &[(&str, &str)] = &[("skipped", "why")];\n'
        'const CRATE_KINDS: &[&str] = &["rust_library", "rust_binary"];\n'
        'const COMPILED_SOURCE_DIRS: &[&str] = &["src", "examples"];\n'
    )
    library = {"kind": "rust_library", "package": "pkg", "root": "pkg/src/lib.rs", "testonly": False}

    def case(name: str, expect: str | None, *, extra: str = "", rows: dict | None = None,
             files: dict[str, str] | None = None,
             srcs: str = 'glob(["src/**/*.rs", "examples/**/*.rs"])') -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = {
                f"pkg/{rel}": text.replace("mod missing;\n", "")
                for rel, text in _module_tree.FIXTURE.items()
                if rel.startswith("src/")
            }
            _module_tree.materialize_fixture(root, {**fixture, **(files or {})})
            (root / GUARD).parent.mkdir(parents=True)
            (root / GUARD).write_text(guard.format(extra=extra))
            (root / "pkg" / "BUILD.bazel").write_text(
                f'filegroup(\n    name = "guard_src_files",\n    srcs = {srcs},\n)\n'
            )
            (root / TARGET_TABLE).parent.mkdir(parents=True)
            (root / TARGET_TABLE).write_text(json.dumps({"targets": rows or {"//pkg:lib": library}}))
            found, checked = check_source_trees(root)
        if checked == 0:
            print(f"SELFTEST FAILED [{name}]: no file was checked — a vacuous pass")
            return False
        if expect is None and found or expect is not None and (len(found) != 1 or expect not in found[0]):
            print(f"SELFTEST FAILED [{name}]: expected {expect!r}, got {found}")
            return False
        return True

    ok = case("the fixture crate, scanned, every file in a walked and globbed directory", None)
    ok &= case(
        "a crate package in neither list",
        "in neither CRATE_SOURCE_TREES nor NOT_SCANNED",
        rows={"//pkg:lib": library, "//other:lib": {**library, "package": "other", "root": "pkg/src/lib.rs"}},
    )
    ok &= case(
        "a hand-listed package that compiles no crate",
        "compiles no crate",
        extra='    ("gone", "TREE_GONE"),\n',
    )
    ok &= case(
        "a `#[path]` module outside the walked directories",
        "outside the",
        files={
            "pkg/src/lib.rs": '#[path = "../shared/x.rs"]\nmod x;\n',
            "pkg/shared/x.rs": "",
        },
    )
    ok &= case(
        "an example binary the glob leaves out of the runfiles",
        "does not glob",
        rows={"//pkg:lib": library, "//pkg:demo": {**library, "kind": "rust_binary", "root": "pkg/examples/demo.rs"}},
        files={"pkg/examples/demo.rs": ""},
        srcs='glob(["src/**/*.rs"])',
    )
    ok &= case(
        "a compiled file the glob's `exclude` leaves out of the runfiles",
        "does not glob",
        srcs='glob(\n        ["src/**/*.rs", "examples/**/*.rs"],\n        exclude = ["src/alpha/deep.rs"],\n    )',
    )
    ok &= case(
        "an `exclude` naming no compiled file excludes nothing",
        None,
        srcs='glob(["src/**/*.rs", "examples/**/*.rs"], exclude = ["src/never.rs"])',
    )
    ok &= case(
        "a `srcs` shape the gate does not read is a finding, not a guess",
        "does not read",
        srcs='glob(["src/**/*.rs", "examples/**/*.rs"]) + ["extra.rs"]',
    )
    ok &= case(
        "a trailing `**` crosses `/`, as Bazel's glob does",
        None,
        srcs='glob(["src/**", "examples/**"])',
    )
    ok &= case(
        "a test-only target's sources are test sources",
        None,
        rows={
            "//pkg:lib": library,
            "//pkg:fixture": {**library, "root": "pkg/tests/fixture/lib.rs", "testonly": True},
        },
        files={"pkg/tests/fixture/lib.rs": ""},
    )
    return ok


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    library_findings, libraries = check_libraries(REPO)
    tree_findings, tree_files = check_source_trees(REPO)
    findings = library_findings + tree_findings
    if findings:
        print("bazel srcs gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nA hand list drifts silently: the module tree moves, the list does not. Add the "
            "file or the package to the list.",
            file=sys.stderr,
        )
        return 1
    if not libraries:
        print(
            f"bazel srcs gate: FAIL — {TARGET_TABLE} holds no library target, so this gate "
            f"checked nothing; a pass here would be vacuous.",
            file=sys.stderr,
        )
        return 1
    print(
        f"bazel srcs gate: OK — the module tree of each of {libraries} library target(s) is "
        f"in its srcs; the audit-vocabulary guard's source trees carry all {tree_files} "
        f"file(s) its crates' targets compile"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
