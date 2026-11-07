# SPDX-License-Identifier: Apache-2.0
"""The `--selftest` of the production view: region cases, projections and the file walk."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _rust_source_lex import code_only
from _rust_source_view import production_view
from _rust_source_walk import crate_sources

#: `(label, source, expected production line count)`.
REGION_CASES: list[tuple[str, str, int]] = [
    ("no test module", "fn a() {}\nfn b() {}\n", 2),
    ("a `#![cfg(test)]` first line makes the whole file test code", "// doc\n#![cfg(test)]\nfn a() {}\nfn b() {}\n", 0),
    ("`#![cfg(test)]` below code is not a whole-file attribute", "fn a() {}\n#![cfg(test)]\nfn b() {}\n", 3),
    ("narrow #[cfg(test)]", "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n", 1),
    (
        "#[cfg(all(test, unix))] — the form that broke the first census",
        "fn a() {}\nfn b() {}\n#[cfg(all(test, unix))]\nmod tests {\n    fn t() {}\n}\n",
        2,
    ),
    (
        "production code AFTER the test region is counted",
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\nfn c() {}\n",
        3,
    ),
    (
        "nested braces inside the test module do not end it early",
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { if x { y(); } }\n    fn u() {}\n}\n",
        1,
    ),
    (
        "two test regions",
        "fn a() {}\n#[cfg(test)]\nmod t1 {\n}\nfn b() {}\n#[cfg(all(test, feature = \"x\"))]\nmod t2 {\n}\nfn c() {}\n",
        3,
    ),
    (
        "#[cfg(test)] on a const closes at its `;` — the item BELOW it is production",
        '#[cfg(test)]\nconst K: &str = "k";\nimpl Drop for T {\n    fn drop(&mut self) {}\n}\n',
        3,
    ),
    ("#[cfg(test)] on a `use` closes at its `;`", "#[cfg(test)]\nuse std::x::Y;\nfn a() {}\nfn b() {}\n", 2),
    (
        "a multi-line #[cfg(test)] const still closes at its own `;`",
        '#[cfg(test)]\nconst K: &[&str] = &[\n    "a",\n];\nfn a() {}\n',
        1,
    ),
    (
        "an attribute followed by a comment still reaches the item it introduces",
        "#[cfg(test)]\n// a note\nmod tests {\n    fn t() {}\n}\nfn a() {}\n",
        1,
    ),
    (
        "a brace inside a string in the test module is not a brace",
        'fn a() {}\n#[cfg(test)]\nmod tests {\n    const S: &str = "{";\n}\nfn b() {}\n',
        2,
    ),
    (
        "a brace inside a raw byte string spanning lines is not a brace",
        'fn a() {}\n#[cfg(test)]\nmod tests {\n    const J: &[u8] = br#"{"e":{\n"d":{}}}"#;\n}\nfn b() {}\n',
        2,
    ),
    (
        "a brace inside a char literal or a comment is not a brace",
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    const C: char = '{'; // }\n    /* } */\n}\nfn b() {}\n",
        2,
    ),
    (
        "a `;` inside a string on the attributed line does not close a braced item",
        '#[cfg(test)]\nmod tests { const S: &str = ";";\n    fn t() {}\n}\nfn a() {}\n',
        1,
    ),
    ("empty file", "", 0),
]


class _Report:
    """Prints one line per case and counts the failures."""

    def __init__(self) -> None:
        self.failures = 0

    def case(self, label: str, ok: bool, got: object) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failures += 1
            print(f"        got {got!r}")


def _region_cases(report: _Report) -> None:
    for label, text, expected in REGION_CASES:
        got = len(production_view(text))
        report.case(label, got == expected, got)


def _projection_cases(report: _Report) -> None:
    view = production_view("fn a() {}\n#[cfg(test)]\nmod t {}\nfn b() {}\n")
    report.case("the line map names the original lines", [n for n, _ in view.lines] == [1, 4], view.lines)

    src = 'fn f() -> &str { "Mcp-Name" } // x\n/* y */ fn g() { let c = \'{\'; }\n'
    code = production_view(src).code()
    report.case(
        "code() blanks comments and literals and keeps line structure",
        "Mcp-Name" not in code and "x" not in code and "y" not in code and "{'" not in code
        and code.count("\n") == src.count("\n") - 1 and "fn g()" in code.split("\n")[1],
        code,
    )
    kept = production_view(src).without_comments()
    report.case("without_comments() keeps the literal", '"Mcp-Name"' in kept and "// x" not in kept, None)


def _numbering_cases(report: _Report) -> None:
    numbered = production_view("// only a comment\nfn a() {} // tail\n\nfn b() {}\n").numbered_code()
    report.case("numbered_code() drops comment-only and blank lines", [n for n, _ in numbered] == [2, 4], numbered)
    report.case(
        "a `mod` in a raw string or a doc comment is blanked",
        "mod" not in code_only('/// mod ghost\nconst X: &str = r#"mod ghost"#;\n'),
        None,
    )


def _lexing_cases(report: _Report) -> None:
    in_comment = "/*\n#[cfg(test)]\n*/\npub fn prod() {}\n"
    report.case("a #[cfg(test)] inside a block comment opens no region", len(production_view(in_comment)) == 4, production_view(in_comment).lines)
    in_raw = 'const S: &str = r#"\n#[cfg(test)]\n"#;\npub fn prod() {}\n'
    report.case("a #[cfg(test)] inside a raw string opens no region", len(production_view(in_raw)) == 4, production_view(in_raw).lines)
    crlf = "fn a() {}\r\n#[cfg(test)]\r\nmod t {}\r\nfn b() {}\r\n"
    report.case("CRLF text keeps raw and code-only lines aligned", len(production_view(crlf)) == 2, production_view(crlf).lines)
    report.case("a lifetime is not a char literal", code_only("fn f<'a>(x: &'a str) {}") == "fn f<'a>(x: &'a str) {}", None)


def _walk_cases(report: _Report) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "Cargo.toml").write_text("")
        (root / "testonly").mkdir()
        (root / "testonly" / "Cargo.toml").write_text("")
        for rel in ("testonly/tests/t.rs", "src/lib.rs", "src/a/b.rs", "src/tests/t.rs", "src/examples/mod.rs", "tests/it.rs", "benches/b.rs", "examples/e.rs", "build.rs", "target/x.rs", "vendor/v.rs"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        got = [p.relative_to(root).as_posix() for p in crate_sources(root)]
        want = ["src/a/b.rs", "src/examples/mod.rs", "src/lib.rs", "src/tests/t.rs"]
        report.case("crate_sources walks production modules only", got == want, got)
        got = [p.relative_to(root / "src").as_posix() for p in crate_sources(root / "src")]
        report.case("a walk rooted at src/ keeps src/examples and src/tests", got == ["a/b.rs", "examples/mod.rs", "lib.rs", "tests/t.rs"], got)


def selftest() -> int:
    report = _Report()
    _region_cases(report)
    _projection_cases(report)
    _numbering_cases(report)
    _lexing_cases(report)
    _walk_cases(report)
    if report.failures:
        print(f"rust source: SELFTEST FAILED ({report.failures})")
        return 1
    print("rust source: selftest passed")
    return 0
