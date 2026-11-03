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

import functools
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _rust_source import TEST_ATTR, code_only  # noqa: E402

#: A module declaration in code-only text: optional visibility, `mod`, the name, then `;`
#: (a file module) or `{` (an inline one).
_DECL = re.compile(
    r"(?<![A-Za-z0-9_])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*([;{])"
)
_TOKENS = re.compile(r"#!?\[|[{};]")
_PATH_ATTR = re.compile(r'^#\[\s*path\s*=\s*"([^"]*)"\s*\]$', re.S)


# ------------------------------------------------------------------------ declarations


@dataclass(frozen=True)
class Declaration:
    """One `mod` declaration in one file."""

    name: str
    #: 1-based line of the `mod` keyword.
    line: int
    #: `mod x { … }` rather than `mod x;`.
    inline: bool
    #: The outer attributes written on the declaration, as code text (`#[cfg(test)]`, …).
    attributes: tuple[str, ...]
    #: The inline modules the declaration sits inside, outermost first, as
    #: `(name, path attribute or None)`.
    enclosing: tuple[tuple[str, str | None], ...]
    #: For an inline module, the 1-based line of its closing brace; 0 otherwise.
    end_line: int = 0
    #: Whether an enclosing inline module is `#[cfg(test)]`.
    in_test_region: bool = False

    @property
    def path_attribute(self) -> str | None:
        for attribute in self.attributes:
            match = _PATH_ATTR.match(attribute)
            if match:
                return match.group(1)
        return None

    @property
    def cfg_test(self) -> bool:
        """Compiled only under test: its own attribute, or an enclosing test module's."""
        return self.in_test_region or any(TEST_ATTR.match(a) for a in self.attributes)


def _attribute_end(code: str, start: int) -> int:
    depth = 0
    for j in range(start, len(code)):
        if code[j] == "[":
            depth += 1
        elif code[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(code)


def declarations(text: str) -> list[Declaration]:
    """Every `mod` declaration in a Rust source, in source order, from code only."""
    code = code_only(text)
    line_starts = [0] + [i + 1 for i, ch in enumerate(code) if ch == "\n"]

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts)
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid
        return lo + 1

    out: list[Declaration] = []
    #: (start, end, text) of each outer attribute, for reading those a declaration carries.
    attributes: dict[int, tuple[int, str]] = {}
    #: Open braces: the inline module each one opened (an index into `out`), or None.
    braces: list[int | None] = []
    pos = 0
    # The first declaration at or after `pos` stays the first one until `pos` passes its
    # start, so it is searched for again only then; searching on every token re-scanned the
    # rest of the file once per token.
    decl = _DECL.search(code, pos)
    while True:
        if decl is not None and decl.start() < pos:
            decl = _DECL.search(code, pos)
        token = _TOKENS.search(code, pos)
        if token is None and decl is None:
            break
        if decl is not None and (token is None or decl.start() <= token.start()):
            carried: list[str] = []
            j = decl.start()
            while True:
                k = j
                while k and code[k - 1].isspace():
                    k -= 1
                attribute = attributes.get(k)
                if attribute is None:
                    break
                carried.insert(0, attribute[1])
                j = attribute[0]
            enclosing_idx = [b for b in braces if b is not None]
            enclosing = tuple((out[b].name, out[b].path_attribute) for b in enclosing_idx)
            in_test = any(out[b].cfg_test for b in enclosing_idx)
            inline = decl.group(2) == "{"
            out.append(
                Declaration(
                    name=decl.group(1),
                    line=line_of(decl.start()),
                    inline=inline,
                    attributes=tuple(carried),
                    enclosing=enclosing,
                    in_test_region=in_test,
                )
            )
            if inline:
                braces.append(len(out) - 1)
            pos = decl.end()
            continue
        assert token is not None
        lexeme = token.group(0)
        if lexeme.startswith("#"):
            end = _attribute_end(code, token.start() + len(lexeme) - 1)
            if lexeme == "#[":
                # From the source, not the blanked code: `#[path = "…"]` is a string.
                attributes[end] = (token.start(), " ".join(text[token.start() : end].split()))
            pos = end
        elif lexeme == "{":
            braces.append(None)
            pos = token.end()
        elif lexeme == "}":
            if braces:
                opened = braces.pop()
                if opened is not None:
                    d = out[opened]
                    out[opened] = Declaration(
                        d.name, d.line, d.inline, d.attributes, d.enclosing, line_of(token.start()), d.in_test_region
                    )
            pos = token.end()
        else:
            pos = token.end()
    return out


def read_declarations(path: Path) -> list[Declaration]:
    """`declarations` of a file, parsed once per version of the file."""
    stat = path.stat()
    return list(_cached_declarations(path.resolve(), stat.st_mtime_ns, stat.st_size))


@functools.lru_cache(maxsize=4096)
def _cached_declarations(path: Path, _mtime_ns: int, _size: int) -> tuple[Declaration, ...]:
    return tuple(declarations(path.read_text(encoding="utf-8", errors="replace")))


# -------------------------------------------------------------------------- resolution


@dataclass(frozen=True)
class Child:
    """A file-module declaration and the file it names (`None` when no file answers)."""

    declaration: Declaration
    file: Path | None
    #: Whether `file` is a mod-rs file — its own children live beside it.
    mod_rs: bool


def is_mod_rs_name(path: Path) -> bool:
    """The file names that are mod-rs wherever they appear. A crate root of any other name,
    or a file loaded through `#[path]`, is mod-rs too, which only a walk knows."""
    return path.name in ("mod.rs", "lib.rs", "main.rs")


def children(path: Path, *, mod_rs: bool) -> list[Child]:
    """Every `mod x;` in `path`, resolved as rustc resolves it.

    `mod_rs` is how `path` was loaded: True for a crate root, a `mod.rs` and a `#[path]`
    file, False for a file reached as `name.rs`.
    """
    directory = path.parent
    offset = None if mod_rs else path.stem
    out: list[Child] = []
    for decl in read_declarations(path):
        if decl.inline:
            continue
        here, here_offset = directory, offset
        for name, explicit in decl.enclosing:
            if explicit is not None:
                here, here_offset = here / explicit, None
            else:
                here = here / here_offset / name if here_offset else here / name
                here_offset = None
        explicit = decl.path_attribute
        if explicit is not None:
            candidate = here / explicit
            out.append(Child(decl, candidate if candidate.is_file() else None, True))
            continue
        base = here / here_offset if here_offset else here
        file_form, dir_form = base / f"{decl.name}.rs", base / decl.name / "mod.rs"
        if file_form.is_file():
            out.append(Child(decl, file_form, False))
        elif dir_form.is_file():
            out.append(Child(decl, dir_form, True))
        else:
            out.append(Child(decl, None, False))
    return out


@dataclass(frozen=True)
class ModuleFile:
    """A file a crate root reaches."""

    path: Path
    #: The module path from the crate root; `()` for the root itself.
    module: tuple[str, ...]
    #: The file whose declaration reached this one; `None` for the root.
    declared_by: Path | None
    declaration: Declaration | None
    #: Reachable only through a `#[cfg(test)]` declaration on the way from the root.
    test_only: bool


@dataclass(frozen=True)
class Tree:
    """The module tree of one crate root."""

    root: Path
    files: tuple[ModuleFile, ...]
    #: `(declaring file, declaration)` for every `mod x;` that names no file.
    unresolved: tuple[tuple[Path, Declaration], ...]

    def by_module(self) -> dict[tuple[str, ...], Path]:
        return {f.module: f.path for f in self.files}

    def paths(self) -> set[Path]:
        return {f.path for f in self.files}


def walk(root: Path) -> Tree:
    """The module tree a crate root reaches, depth first in declaration order."""
    files: list[ModuleFile] = []
    unresolved: list[tuple[Path, Declaration]] = []
    seen: set[Path] = set()

    def visit(path: Path, module: tuple[str, ...], by: Path | None, decl: Declaration | None, mod_rs: bool, test: bool) -> None:
        key = path.resolve()
        if key in seen:
            return
        seen.add(key)
        files.append(ModuleFile(path, module, by, decl, test))
        for child in children(path, mod_rs=mod_rs):
            inner = tuple(name for name, _ in child.declaration.enclosing)
            if child.file is None:
                unresolved.append((path, child.declaration))
                continue
            visit(
                child.file,
                module + inner + (child.declaration.name,),
                path,
                child.declaration,
                child.mod_rs,
                test or child.declaration.cfg_test,
            )

    visit(root, (), None, None, True, False)
    return Tree(root, tuple(files), tuple(unresolved))


def declaration_chain(root: Path, module: tuple[str, ...]) -> list[Declaration]:
    """The declarations that name each segment of `module`, from `root`, as far as they go.

    An inline module is followed inside its file; a file module moves to its file. The chain
    stops at the first segment no declaration names.
    """
    current, mod_rs = root, True
    inline: tuple[str, ...] = ()
    chain: list[Declaration] = []
    for segment in module:
        decls = read_declarations(current)
        found = next(
            (d for d in decls if d.name == segment and tuple(n for n, _ in d.enclosing) == inline),
            None,
        )
        if found is None:
            break
        chain.append(found)
        if found.inline:
            inline = inline + (segment,)
            continue
        child = next((c for c in children(current, mod_rs=mod_rs) if c.declaration == found), None)
        if child is None or child.file is None:
            break
        current, mod_rs, inline = child.file, child.mod_rs, ()
    return chain


# ---------------------------------------------------------------------- the fixture


#: The one fixture tree every module-resolution self-test reads: both file forms, a
#: `#[path]` from a mod-rs and from a non-mod-rs file, a `#[path]` file's own children, an
#: inline module holding a file module, a test-only module and its child, a commented-out,
#: block-commented, raw-string and char-literal-adjacent `mod`, an unresolved declaration,
#: and a crate root not named `lib.rs`/`main.rs`.
FIXTURE: dict[str, str] = {
    "src/lib.rs": (
        "pub mod alpha;\n"
        "mod beta;\n"
        "// mod ghost_line;\n"
        "/* outer /* inner */\nmod ghost_block;\n*/\n"
        'const F: &str = r#"\nmod ghost_raw;\n"#;\n'
        "const Q: char = '\"';\n"
        '#[path = "elsewhere/gamma_impl.rs"]\n'
        "mod gamma;\n"
        "pub mod outer {\n"
        "    pub mod nested;\n"
        "    mod inline_only {}\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests;\n"
        "mod missing;\n"
    ),
    "src/alpha.rs": 'pub mod deep;\n#[path = "pathed.rs"]\nmod pathed;\n',
    "src/alpha/deep.rs": "",
    "src/pathed.rs": "",
    "src/beta/mod.rs": "mod child;\n",
    "src/beta/child.rs": "",
    "src/elsewhere/gamma_impl.rs": "mod sibling;\n",
    "src/elsewhere/sibling.rs": "",
    "src/outer/nested.rs": "",
    "src/tests.rs": "mod helper;\n",
    "src/tests/helper.rs": "",
    "src/ghost_line.rs": "",
    "src/ghost_block.rs": "",
    "src/ghost_raw.rs": "",
    "tests/suite_test.rs": "mod common;\n",
    "tests/common/mod.rs": "",
}

#: What `walk` must give for each fixture root: module path -> (file, test_only).
FIXTURE_TREES: dict[str, dict[tuple[str, ...], tuple[str, bool]]] = {
    "src/lib.rs": {
        (): ("src/lib.rs", False),
        ("alpha",): ("src/alpha.rs", False),
        ("alpha", "deep"): ("src/alpha/deep.rs", False),
        ("alpha", "pathed"): ("src/pathed.rs", False),
        ("beta",): ("src/beta/mod.rs", False),
        ("beta", "child"): ("src/beta/child.rs", False),
        ("gamma",): ("src/elsewhere/gamma_impl.rs", False),
        ("gamma", "sibling"): ("src/elsewhere/sibling.rs", False),
        ("outer", "nested"): ("src/outer/nested.rs", False),
        ("tests",): ("src/tests.rs", True),
        ("tests", "helper"): ("src/tests/helper.rs", True),
    },
    "tests/suite_test.rs": {
        (): ("tests/suite_test.rs", False),
        ("common",): ("tests/common/mod.rs", False),
    },
}


def materialize_fixture(directory: Path, files: dict[str, str] | None = None) -> Path:
    """Write the fixture tree (or `files`) under `directory` and return it."""
    for rel, content in (FIXTURE if files is None else files).items():
        path = directory / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return directory


def selftest() -> int:
    failures = 0

    def case(label: str, ok: bool, got: object) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            print(f"        got {got!r}")

    with tempfile.TemporaryDirectory() as tmp:
        base = materialize_fixture(Path(tmp))
        for root, expected in FIXTURE_TREES.items():
            tree = walk(base / root)
            got = {f.module: (f.path.relative_to(base).as_posix(), f.test_only) for f in tree.files}
            case(f"the tree of {root} is rustc's", got == expected, got)
        lib = walk(base / "src/lib.rs")
        unresolved = [(p.relative_to(base).as_posix(), d.name) for p, d in lib.unresolved]
        case("an unresolved declaration is reported, not dropped", unresolved == [("src/lib.rs", "missing")], unresolved)
        names = [d.name for d in read_declarations(base / "src/lib.rs")]
        case(
            "a mod in a comment, block comment or raw string declares nothing",
            not {"ghost_line", "ghost_block", "ghost_raw"} & set(names),
            names,
        )
        inline = next(d for d in read_declarations(base / "src/lib.rs") if d.name == "outer")
        case("an inline module records where it closes", inline.inline and inline.end_line == 16, inline)
        chain = [d.name for d in declaration_chain(base / "src/lib.rs", ("outer", "nested"))]
        case("a declaration chain follows an inline module into its file child", chain == ["outer", "nested"], chain)
        chain = [d.name for d in declaration_chain(base / "src/lib.rs", ("gamma", "sibling", "x"))]
        case("a declaration chain follows `#[path]` and stops at a missing segment", chain == ["gamma", "sibling"], chain)
        nested = declarations("#[cfg(test)]\nmod t {\n    mod inner;\n}\n")
        case(
            "a declaration inside a test module is test-only",
            [d.cfg_test for d in nested] == [True, True],
            nested,
        )
        attrs = declarations('#[cfg(feature = "x")]\n#[path = "p.rs"]\npub(crate) mod m;\n')
        case(
            "every attribute on a declaration is kept, in order",
            attrs[0].attributes == ('#[cfg(feature = "x")]', '#[path = "p.rs"]') and attrs[0].path_attribute == "p.rs",
            attrs,
        )
        case(
            "an attribute separated from `mod` by another item is not carried",
            declarations("#[cfg(test)]\nfn f() {}\nmod m;\n")[0].attributes == (),
            None,
        )
    if failures:
        print(f"module tree: SELFTEST FAILED ({failures})")
        return 1
    print("module tree: selftest passed")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
