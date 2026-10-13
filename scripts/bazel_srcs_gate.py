#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bazel srcs gate — a hand-listed `srcs` must match the crate's module tree.

Every crate but one lets Bazel `glob(["src/**/*.rs"])`, which cannot drift from what
cargo compiles. `mcp-re-proxy` hand-lists its sources (`_PROXY_LIB_SRCS`) because
three library flavors share the list, and a hand-list drifts: `src/audit_sink.rs`
landed with the ADR-MCPS-035 audit surface and was never added, so cargo built a
module Bazel could not find and every Bazel target downstream of the proxy library
failed with E0583.

The existing semantic-drift gate compares TARGETS, not sources, so it passed. The
only thing that caught this was a full `bazel test //...` — 30+ minutes, and per its
own commit message it "had never once completed during this audit", which is exactly
how the miss survived several rounds of review.

This is that check at one second. For every crate whose library sources are hand
listed, it walks the module tree from `lib.rs` and requires that each declared
module's declaration file appears in the list, and that each listed file exists.

Three properties are load-bearing, because each one had a silent-blindness failure
mode:

- **Only a glob over `src/` exempts a crate.** A crate is exempt when its library
  sources cannot drift, not when the word `glob` occurs somewhere in its BUILD file.
  `mcp-re-proxy` globs its integration-test sources while hand-listing its library.
- **The module tree is rustc's.** `tools/verification/_module_tree.py` owns it: both
  file forms, `#[path]`, inline modules, and declarations read from code only. A walk
  that stops at a resolved file observes nothing after the first file-to-directory
  split, which is precisely when a hand-list starts to drift.

The second hand list is the audit-vocabulary guard's: `CRATE_SOURCE_TREES` names the
crate packages it scans, `COMPILED_SOURCE_DIRS` the directories it walks in each, and each
package's `guard_src_files` glob the files its runfiles carry. A crate package missing from
the list, a file a crate target reaches outside those directories, or one the glob leaves
out of the runfiles, is a file the guard never reads while it reports a clean scan. Each is
checked against the module tree of every crate target the build graph compiles.

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

import _module_tree  # noqa: E402

SRC_ENTRY = re.compile(r'"(src/[A-Za-z0-9_/]+\.rs)"')
# A glob reaching into `src/`. Undriftable ONLY when it is the value of the PRODUCTION
# LIBRARY target's `srcs` — see `library_srcs`.
SRC_GLOB = re.compile(r'glob\(\s*\[[^]]*"src/')

#: A top-level Starlark list variable, e.g. `_PROXY_LIB_SRCS = [...]`. Resolved because
#: `srcs = _PROXY_LIB_SRCS` is how the largest crate here declares its library.
LIST_VAR = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[", re.M)

#: A top-level rule call: an identifier at column 0 followed by `(`.
RULE_CALL = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)\s*\(", re.M)

#: Rule names that declare a Rust LIBRARY. The gate's subject is the crate's library
#: module tree rooted at `src/lib.rs`, so only these targets can answer for it.
LIBRARY_RULE = re.compile(r"(?:^|_)rust_library$")


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


def list_variables(build_text: str) -> dict[str, str]:
    """Top-level `NAME = [ ... ]` assignments, as raw text."""
    return {
        m.group(1): balanced(build_text, build_text.index("[", m.start()), "[", "]")
        for m in LIST_VAR.finditer(build_text)
    }


def rule_calls(build_text: str) -> list[tuple[str, str]]:
    """Every top-level `rule_name( ... )`, as `(rule_name, body)`."""
    calls = []
    for m in RULE_CALL.finditer(build_text):
        body = balanced(build_text, build_text.index("(", m.start()), "(", ")")
        calls.append((m.group(1), body))
    return calls


def resolve(value: str, variables: dict[str, str]) -> str:
    """`value` with any bare top-level list variable it names replaced by that list.

    Substitution is textual and one level deep, which is all this repository's BUILD files
    use (`srcs = _PROXY_LIB_SRCS`, `deps = A + B`). A variable the gate cannot resolve stays
    as its own name and simply contributes no `src/` entries — the conservative direction,
    because an unresolved list makes the gate demand MORE, never less.
    """
    out = value
    for name, text in variables.items():
        out = re.sub(r"\b%s\b" % re.escape(name), text, out)
    return out


def library_srcs(build_text: str) -> str | None:
    """The resolved `srcs` of the production library target(s) that own `src/lib.rs`.

    THE POINT. The proposition this gate checks is not "some target in this BUILD has a
    srcs glob" — it is "the production LIBRARY target whose Rust module tree is being
    checked has an undriftable srcs definition". Those differ, and the difference is a
    false green: a `rust_test` carrying `srcs = glob(["src/**/*.rs"])` next to a
    hand-listed `rust_library` would otherwise exempt the whole crate, which is the same
    defect as the earlier `data = glob(...)` one at a different attribute.

    So `srcs` is read from the LIBRARY targets and from nowhere else, and the hand-listed
    set the module walk is checked against comes from the same place. A file named only by
    a test target's `srcs` or `data` is not something the compiler is handed for the
    library, and must not satisfy a `mod` declaration in it.

    Returns the concatenated `srcs` text of every library target that owns `src/lib.rs`, or
    `None` when the BUILD declares no such target.
    """
    variables = list_variables(build_text)
    owning: list[str] = []
    for rule_name, body in rule_calls(build_text):
        if not LIBRARY_RULE.search(rule_name):
            continue
        match = re.search(r"\bsrcs\s*=", body)
        if not match:
            continue
        srcs = resolve(attribute_value(body, match.end()), variables)
        # A library owns the crate root either by naming it or by globbing over it.
        if '"src/lib.rs"' in srcs or SRC_GLOB.search(srcs):
            owning.append(srcs)
    return "\n".join(owning) if owning else None


def check_module_tree(crate: Path, listed: set[str]) -> list[str]:
    """Findings for every file the library's module tree reaches, and every declaration
    that reaches none.

    The tree is walked to the bottom even under an unlisted file: one run names every
    missing entry, not one per re-run.
    """
    findings: list[str] = []
    tree = _module_tree.walk(crate / "src" / "lib.rs")
    for module in tree.files[1:]:
        rel = module.path.relative_to(crate).as_posix()
        if rel not in listed:
            declared = module.declared_by.relative_to(crate).as_posix() if module.declared_by else "?"
            findings.append(
                f"{crate.name}/BUILD.bazel: `mod {module.module[-1]};` in {declared} needs {rel} "
                f"in the hand-listed srcs — rustc compiles it, Bazel cannot find it (E0583)"
            )
    for declaring, decl in tree.unresolved:
        findings.append(
            f"{crate.name}: `mod {decl.name};` in {declaring.relative_to(crate).as_posix()} "
            f"names no file — rustc cannot compile it either"
        )
    return findings


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


def _glob_matches(pattern: str, path: str) -> bool:
    regex = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, path) is not None


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
                not any(_glob_matches(p, within) for p in read[0])
                or any(_glob_matches(p, within) for p in read[1])
            ):
                findings.append(
                    f"{label} compiles {rel}, which {package}:guard_src_files does not glob — "
                    f"the guard's runfiles do not carry it"
                )
    return findings, checked


def check_crate(crate: Path) -> list[str]:
    """Findings for one crate. Empty when the library globs or the list is complete."""
    build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
    if not build.is_file() or not lib.is_file():
        return []
    build_text = build.read_text(errors="replace")
    srcs = library_srcs(build_text)
    if srcs is None:
        return []  # no library target here to answer for the module tree
    if SRC_GLOB.search(srcs):
        return []  # cannot drift

    listed = set(SRC_ENTRY.findall(srcs))
    if not listed:
        return []  # nothing hand-listed to check

    findings: list[str] = []
    if "src/lib.rs" not in listed:
        findings.append(
            f"{crate.name}/BUILD.bazel: hand-lists sources without src/lib.rs — "
            f"the crate root itself is missing"
        )
    findings.extend(check_module_tree(crate, listed))

    for entry in sorted(listed):
        if not (crate / entry).is_file():
            findings.append(
                f"{crate.name}/BUILD.bazel: lists {entry}, which does not exist"
            )
    return findings


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for crate in sorted(root.glob("mcp-re-*")):
        if crate.is_dir():
            findings.extend(check_crate(crate))
    return findings


def checked_crates(root: Path) -> list[str]:
    """The crates this gate actually examines — what a green run measured."""
    names = []
    for crate in sorted(root.glob("mcp-re-*")):
        build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
        if not crate.is_dir() or not build.is_file() or not lib.is_file():
            continue
        srcs = library_srcs(build.read_text(errors="replace"))
        if srcs is None or SRC_GLOB.search(srcs) or not SRC_ENTRY.search(srcs):
            continue
        names.append(crate.name)
    return names


def selftest() -> int:  # noqa: C901 — a control per property, each one named
    def case(name: str, build: str, files: dict[str, str], expect: str | None) -> bool:
        """Build a crate, scan it, and compare against one expected finding.

        `expect` is a substring the single finding must contain, or None for
        "this tree is correct and must produce nothing".

        `build` is wrapped in an `nt_rust_library(...)` call unless it already declares one:
        the gate reads `srcs` from the LIBRARY TARGET, so a fixture that were only a bare
        attribute would exercise a shape no BUILD file has and would pass by finding no
        library at all.
        """
        if "rust_library(" not in build:
            body = build.strip()
            build = 'nt_rust_library(\n    name = "thing",\n    ' + body + '\n)\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = root / "mcp-re-thing"
            (crate / "src").mkdir(parents=True)
            for rel, content in files.items():
                path = crate / "src" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            (crate / "BUILD.bazel").write_text(build)
            found = scan(root)
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
    # `_module_tree`'s selftest. What this gate adds is the hand-list against that tree.
    fixture = {
        rel[len("src/"):]: text
        for rel, text in _module_tree.FIXTURE.items()
        if rel.startswith("src/") and "mod missing;" not in text
    }
    fixture["lib.rs"] = _module_tree.FIXTURE["src/lib.rs"].replace("mod missing;\n", "")
    reached = sorted(
        path for path, _ in _module_tree.FIXTURE_TREES["src/lib.rs"].values()
    )
    listing = "srcs = [" + ", ".join(f'"{p}"' for p in reached) + "]\n"
    ok &= case("the fixture tree, every reached file listed", listing, fixture, None)
    ok &= case(
        "the fixture tree, a file reached only through `#[path]` unlisted",
        listing.replace('"src/elsewhere/sibling.rs", ', ""),
        fixture,
        "needs src/elsewhere/sibling.rs",
    )
    ok &= case(
        "the fixture tree, the child of an inline module unlisted",
        listing.replace('"src/outer/nested.rs", ', ""),
        fixture,
        "needs src/outer/nested.rs",
    )
    ok &= case(
        "file module, one missing — the defect that shipped",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )

    # --- exemption and staleness ------------------------------------------------
    ok &= case(
        "a glob over src/ is exempt",
        'srcs = glob(["src/**/*.rs"]),\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        None,
    )
    ok &= case(
        "a glob over tests/ does NOT exempt a hand-listed library",
        'nt_rust_library(\n'
        '    name = "thing",\n'
        '    srcs = ["src/lib.rs", "src/alpha.rs"],\n'
        ")\n"
        "nt_rust_test(\n"
        '    srcs = glob(["tests/integration/*.rs"]) + ["src/lib.rs"],\n'
        ")\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a `data` glob over src/ does NOT exempt a hand-listed library",
        # The first measured regression: a test target listing serving sources in `data` so
        # its runfiles contain them made the whole crate read as undriftable, and the gate
        # reported a clean pass over a library nobody was checking any more.
        'nt_rust_library(\n'
        '    name = "thing",\n'
        '    srcs = ["src/lib.rs", "src/alpha.rs"],\n'
        ")\n"
        "nt_rust_test(\n"
        '    srcs = glob(["tests/integration/*.rs"]),\n'
        '    data = glob(["src/**/*.rs"]),\n'
        ")\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "an unrelated TEST target's own srcs glob over src/ does NOT exempt the library",
        # THE POISON PILL. The first repair asked "does any `srcs` attribute glob into
        # `src/`", which is a different proposition from "does the production LIBRARY have
        # an undriftable srcs". A `rust_test` compiling the library's sources into its own
        # crate is a real shape, and under the looser question it exempted everything.
        'nt_rust_library(\n'
        '    name = "thing",\n'
        '    srcs = ["src/lib.rs", "src/alpha.rs"],\n'
        ")\n"
        "nt_rust_test(\n"
        '    name = "thing_test",\n'
        '    srcs = glob(["src/**/*.rs"]),\n'
        ")\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a library declaring its srcs through a top-level list variable is read",
        "_LIB_SRCS = [\n"
        '    "src/lib.rs",\n'
        '    "src/alpha.rs",\n'
        "]\n"
        'nt_rust_library(\n'
        '    name = "thing",\n'
        "    srcs = _LIB_SRCS,\n"
        ")\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a file named only by a TEST target does not satisfy the library's mod",
        # The same binding, in the other direction: the hand-listed set comes from the
        # library's srcs, so a `beta.rs` the compiler is handed only for a test crate must
        # not answer for a `mod beta;` in the library.
        'nt_rust_library(\n'
        '    name = "thing",\n'
        '    srcs = ["src/lib.rs", "src/alpha.rs"],\n'
        ")\n"
        "nt_rust_test(\n"
        '    srcs = ["src/beta.rs"],\n'
        ")\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a multi-line srcs glob over src/ is still exempt",
        "srcs = glob([\n"
        '        "src/**/*.rs",\n'
        "    ]) + [\n"
        '        "src/lib.rs",\n'
        "    ],\n",
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        None,
    )
    ok &= case(
        "a listed file that does not exist",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs", "src/gone.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "does not exist",
    )
    ok &= case(
        "a mod that resolves to no file at all",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n',
        {"lib.rs": "pub mod alpha;\npub mod nowhere;\n", "alpha.rs": ""},
        "names no file",
    )

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
    crates = checked_crates(REPO)
    tree_findings, tree_files = check_source_trees(REPO)
    findings = scan(REPO) + tree_findings
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
    if not crates:
        print(
            "bazel srcs gate: FAIL — no crate hand-lists its library sources, so this "
            "gate checked nothing. Either the hand-list moved or the exemption rule "
            "is wrong; a pass here would be vacuous.",
            file=sys.stderr,
        )
        return 1
    print(
        f"bazel srcs gate: OK — module tree matches the hand-listed srcs in "
        f"{', '.join(crates)}; the audit-vocabulary guard's source trees carry all "
        f"{tree_files} file(s) its crates' targets compile"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
