# SPDX-License-Identifier: Apache-2.0
"""The production view of a Rust source file, and the walk that finds the files.

The one owner of two questions every source-reading gate asks:

  * **which lines of a file are production** — every line NOT inside a test region. A region
    opens at a line whose attribute matches `^#[cfg((all()?test` and closes with the item that
    attribute introduces: at the matching close brace of a braced item, or at the `;` of an
    item with no braces (a `const`, a `use`, a type alias). Counting resumes afterwards, and a
    file may hold several regions. Braces are counted over CODE characters only, carried across
    lines: a brace inside a string, a raw string, a char literal or a comment is not a brace.
    ADR-MCPRE-061 §5.1 describes this rule; this module defines it.

  * **which files are production Rust** — every `.rs` under a root, minus build outputs,
    vendored trees, `tests/`, `benches/`, `examples/` and `build.rs`.

Each consumer then asks only its own question of the view: a count, a vocabulary, a call
site, a `mod` declaration. Two projections serve those questions. `code()` blanks comments
AND literals, for a gate whose claim is about tokens the compiler sees (`thread::spawn`,
`crate::x::Y`, `getrandom`). `without_comments()` blanks comments and KEEPS literals, for a
gate whose claim includes a header name or an error string. Both keep line structure, so a
finding still names the line it came from.

The rule is also stated in Rust by `mcp-re-test-paths/src/rust_source.rs`, for the gates that
run as Rust tests. The two decide the same fact and must not drift.

Run:  python3 tools/verification/_rust_source.py --selftest
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

#: ADR-MCPRE-061 §5.1. Both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

#: Directories that are not this repository's production Rust.
SKIP_DIRS = {"target", "node_modules", ".git", "bazel-out", "vendor"}

#: Directories under a crate whose Rust is compiled into no shipped library or binary.
NON_PRODUCTION_DIRS = {"tests", "benches", "examples"}

_IDENT = re.compile(r"[A-Za-z0-9_]")


# ------------------------------------------------------------------------------- lexing


def code_only(text: str, *, literals: bool = False) -> str:
    """`text` with comments blanked, and string and char literals blanked unless `literals`.

    Line structure and columns are preserved. Rust block comments nest; a raw string
    `r#"…"#` closes only at its own hash count; a `'` that is not a char literal is a
    lifetime and stays.
    """
    out: list[str] = []
    i, n = 0, len(text)

    def blank(upto: int) -> None:
        nonlocal i
        out.extend("\n" if ch == "\n" else " " for ch in text[i:upto])
        i = upto

    def keep(upto: int) -> None:
        nonlocal i
        out.append(text[i:upto])
        i = upto

    literal = keep if literals else blank
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            blank(n if j < 0 else j)
        elif c == "/" and nxt == "*":
            blank(_block_comment_end(text, i))
        elif c == '"' or (c == "r" and _raw_string_here(text, i)) or (c == "b" and _byte_string_here(text, i)):
            literal(_string_end(text, i))
        elif c == "'" and _char_literal_end(text, i) > i + 1:
            literal(_char_literal_end(text, i))
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _block_comment_end(text: str, i: int) -> int:
    depth, j, n = 0, i, len(text)
    while j < n:
        if text.startswith("/*", j):
            depth += 1
            j += 2
        elif text.startswith("*/", j):
            depth -= 1
            j += 2
            if depth == 0:
                break
        else:
            j += 1
    return j


def _raw_string_here(text: str, i: int) -> bool:
    """True when the `r` at `i` opens a raw string rather than ending an identifier."""
    if i and _IDENT.match(text[i - 1]) and not (text[i - 1] == "b" and (i < 2 or not _IDENT.match(text[i - 2]))):
        return False
    j = i + 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def _byte_string_here(text: str, i: int) -> bool:
    """True when the `b` at `i` opens `b"…"`; `br"…"` is handled at its `r`."""
    return (not i or not _IDENT.match(text[i - 1])) and text.startswith('b"', i)


def _string_end(text: str, i: int) -> int:
    """Index one past the string literal starting at `i`."""
    n = len(text)
    if text[i] == "b":
        i += 1
    if text[i] == "r":
        j = i + 1
        hashes = 0
        while j < n and text[j] == "#":
            hashes += 1
            j += 1
        close = '"' + "#" * hashes
        end = text.find(close, j + 1)
        return n if end < 0 else end + len(close)
    j = i + 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _char_literal_end(text: str, i: int) -> int:
    """Index one past a char literal at `i`; `i + 1` when it is a lifetime."""
    if text.startswith("'\\", i):
        j = text.find("'", i + 2)
        return i + 1 if j < 0 else j + 1
    if i + 2 < len(text) and text[i + 2] == "'":
        return i + 3
    return i + 1


# ------------------------------------------------------------------------ test regions


def _region_end(code_lines: list[str], start: int) -> int:
    """The index just past the test region whose attribute is at `start`.

    `code_lines` is the file with comments and literals already blanked, so every brace
    and `;` seen here is code. A braced item ends at its matching close; an item that
    reaches `;` before any brace ends there, so the next item stays production.
    """
    depth, opened, i = 0, False, start
    while i < len(code_lines):
        code = code_lines[i]
        depth += code.count("{") - code.count("}")
        if "{" in code:
            opened = True
        i += 1
        if opened and depth <= 0:
            return i
        if not opened and depth <= 0 and ";" in code:
            return i
    return i


@dataclass(frozen=True)
class ProductionView:
    """The production lines of one Rust source, each with its 1-based line number."""

    lines: tuple[tuple[int, str], ...]

    def __len__(self) -> int:
        return len(self.lines)

    def text(self) -> str:
        """The production lines as written, joined."""
        return "\n".join(line for _, line in self.lines)

    def code(self) -> str:
        """The production lines with comments and literals blanked; line structure kept."""
        return code_only(self.text())

    def without_comments(self) -> str:
        """The production lines with comments blanked and literals kept."""
        return code_only(self.text(), literals=True)

    def numbered_code(self) -> list[tuple[int, str]]:
        """`(line number, code-only line)` for every production line that has code on it."""
        numbers = [number for number, _ in self.lines]
        out: list[tuple[int, str]] = []
        for number, code in zip(numbers, self.code().split("\n")):
            if code.strip():
                out.append((number, code))
        return out


def production_view(source: str | Path) -> ProductionView:
    """The production view of a Rust source, given its text or its path."""
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    raw = text.splitlines()
    code_lines = code_only(text).split("\n")
    kept: list[tuple[int, str]] = []
    i = 0
    while i < len(raw):
        if TEST_ATTR.match(raw[i].lstrip()):
            i = _region_end(code_lines, i)
            continue
        kept.append((i + 1, raw[i]))
        i += 1
    return ProductionView(tuple(kept))


# -------------------------------------------------------------------------------- walk


def crate_sources(root: Path) -> list[Path]:
    """Every production `.rs` under `root`, sorted.

    Skips build outputs and vendored trees, the `tests/`, `benches/` and `examples/`
    directories, and `build.rs`: none of those is compiled into a shipped library or binary.
    """
    out: list[Path] = []
    for p in sorted(root.rglob("*.rs")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if any(part in NON_PRODUCTION_DIRS for part in rel.parts[:-1]):
            continue
        if p.name == "build.rs":
            continue
        out.append(p)
    return out


# ------------------------------------------------------------------------------ selftest

#: `(label, source, expected production line count)`.
REGION_CASES: list[tuple[str, str, int]] = [
    ("no test module", "fn a() {}\nfn b() {}\n", 2),
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


def selftest() -> int:
    failures = 0

    def case(label: str, ok: bool, got: object) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            print(f"        got {got!r}")

    for label, text, expected in REGION_CASES:
        got = len(production_view(text))
        case(label, got == expected, got)

    view = production_view("fn a() {}\n#[cfg(test)]\nmod t {}\nfn b() {}\n")
    case("the line map names the original lines", [n for n, _ in view.lines] == [1, 4], view.lines)

    src = 'fn f() -> &str { "Mcp-Name" } // x\n/* y */ fn g() { let c = \'{\'; }\n'
    code = production_view(src).code()
    case(
        "code() blanks comments and literals and keeps line structure",
        "Mcp-Name" not in code and "x" not in code and "y" not in code and "{'" not in code
        and code.count("\n") == src.count("\n") - 1 and "fn g()" in code.split("\n")[1],
        code,
    )
    case("without_comments() keeps the literal", '"Mcp-Name"' in production_view(src).without_comments() and "// x" not in production_view(src).without_comments(), None)
    numbered = production_view("// only a comment\nfn a() {} // tail\n\nfn b() {}\n").numbered_code()
    case("numbered_code() drops comment-only and blank lines", [n for n, _ in numbered] == [2, 4], numbered)
    case(
        "a `mod` in a raw string or a doc comment is blanked",
        "mod" not in code_only('/// mod ghost\nconst X: &str = r#"mod ghost"#;\n'),
        None,
    )
    case("a lifetime is not a char literal", code_only("fn f<'a>(x: &'a str) {}") == "fn f<'a>(x: &'a str) {}", None)

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel in ("src/lib.rs", "src/a/b.rs", "src/tests/t.rs", "tests/it.rs", "benches/b.rs", "examples/e.rs", "build.rs", "target/x.rs", "vendor/v.rs"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("")
        got = [p.relative_to(root).as_posix() for p in crate_sources(root)]
        case("crate_sources walks production modules only", got == ["src/a/b.rs", "src/lib.rs"], got)

    if failures:
        print(f"rust source: SELFTEST FAILED ({failures})")
        return 1
    print("rust source: selftest passed")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
