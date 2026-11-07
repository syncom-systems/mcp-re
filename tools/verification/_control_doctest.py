# SPDX-License-Identifier: Apache-2.0
"""Rust doctest controls — the kind ADR-069 §2.1 records as invisible to the first census."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import _rust_targets
from _control_files import skipped
from _control_model import Control
from _control_rust import ATTR_LINE
from _ecosystems import REPO_ROOT

_DOC_FENCE = re.compile(r"^\s*//(/|!)\s*```(.*)$")
_DOC_LINE = re.compile(r"^\s*//[/!]")
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+|async\s+|const\s+|default\s+)*"
    r"(?:fn|struct|enum|trait|type|mod|impl|macro_rules!|union|static|const)\b"
)

#: The fence words rustdoc COMPILES. Anything else — `text`, `ignore`, `sh`, a language
#: name — is prose in a code font and executes nothing. A whitelist rather than a list of
#: inert words, because the failure directions are not symmetric: an unrecognised word
#: treated as inert drops a real control from the census silently, and the census would then
#: report a clean sweep over a population missing exactly the kind ADR-069 §2.1 was written
#: about.
_COMPILED_FENCE = {
    "rust",
    "compile_fail",
    "no_run",
    "should_panic",
    "edition2015",
    "edition2018",
    "edition2021",
    "edition2024",
}

_ITEM_NAME = re.compile(
    r"\b(?:fn|struct|enum|trait|type|mod|union|static|const|macro_rules!)\s+([A-Za-z0-9_]+)"
)


def _fence_mode(words: set[str]) -> str | None:
    """How rustdoc treats this fence: `run`, `compile-only`, `compile-fail`, or None.

    None means the block is not a control at all. The three live modes are distinguished
    because ADR-MCPRE-068 §4.1 refuses to let a compile refusal count as behavioural
    evidence, and a census that flattened them would hand a registration campaign the
    means to do exactly that.
    """
    if words - _COMPILED_FENCE:
        return None
    if "compile_fail" in words:
        return "compile-fail"
    if "no_run" in words:
        return "compile-only"
    return "run"


def _fence_words(info: str) -> set[str]:
    return {word.strip() for word in info.replace(" ", ",").split(",") if word.strip()}


def _item_name(line: str) -> str | None:
    match = _ITEM_NAME.search(line)
    return match.group(1) if match else None


def _doc_module_path(path: Path, source_root: Path) -> tuple[str, ...]:
    parts = list(path.relative_to(source_root).parts)
    last = parts[-1]
    if last in ("lib.rs", "mod.rs"):
        parts = parts[:-1]
    else:
        parts[-1] = last[: -len(".rs")]
    return tuple(parts)


def _attach(found: dict, item: str) -> tuple[int, list[str]]:
    """The `(first line, modes)` accumulator for `item`, created empty if absent."""
    return found.get(item, (1 << 30, []))


@dataclass(frozen=True)
class _Block:
    """An open code fence: where it starts, whether it is `//!`, and its info-string words."""

    start: int
    inner: bool
    words: set[str]


class _DoctestScan:
    """The doctest-bearing ITEMS of one file, accumulated line by line.

    The item, not the example, because that is the granularity the registry claims at: a
    `doc#` symbol selects an item's doctests as a battery (`verify-tests.doc_matches`),
    since a doctest's libtest name embeds the line it starts on and would break on any edit
    above it. An item holding three examples is therefore ONE control, and its modes travel
    with it so a reader can see that what runs there is a compile refusal.
    """

    def __init__(self, base: tuple[str, ...]) -> None:
        self.base = base
        self.module = "::".join(base)
        self.found: dict[str, tuple[int, list[str]]] = {}
        self.pending: list[tuple[int, str]] = []
        self.block: _Block | None = None

    def feed(self, number: int, line: str) -> None:
        fence = _DOC_FENCE.match(line)
        if fence is None:
            self._text(line)
        elif self.block is None:
            self.block = _Block(number, fence.group(1) == "!", _fence_words(fence.group(2)))
        else:
            self._close(self.block)
            self.block = None

    def _close(self, block: _Block) -> None:
        mode = _fence_mode(block.words)
        if mode is None:
            return
        # `//!` documents the enclosing module and never the item below it, so it
        # lands immediately; `///` waits for the item it is attached to.
        if block.inner:
            first, modes = _attach(self.found, self.module)
            self.found[self.module] = (min(first, block.start), modes + [mode])
        else:
            self.pending.append((block.start, mode))

    def _text(self, line: str) -> None:
        if self.block is not None or _DOC_LINE.match(line) or not line.strip():
            return
        if _ITEM.match(line):
            self._item(line)
        elif not ATTR_LINE.match(line):
            self.pending = []

    def _item(self, line: str) -> None:
        if not self.pending:
            return
        name = _item_name(line)
        item = "::".join(self.base + ((name,) if name else ()))
        first, modes = self.found.get(item, (self.pending[0][0], []))
        self.found[item] = (min(first, self.pending[0][0]), modes + [mode for _, mode in self.pending])
        self.pending = []


def _doctests_in(path: Path, package: str, base: tuple[str, ...]) -> list[Control]:
    """The doctest-bearing ITEMS of one file, one control each."""
    scan = _DoctestScan(base)
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        scan.feed(number, line)
    return [
        Control(
            project=package,
            identity=f"doc#{item}",
            kind="rust-doctest",
            carrier=path.relative_to(REPO_ROOT).as_posix(),
            line=first,
            note=", ".join(sorted(set(modes))) + f" ({len(modes)} example(s))",
        )
        for item, (first, modes) in sorted(scan.found.items())
    ]


def _is_documented_source(path: Path, source_root: Path) -> bool:
    """A file inside the library's `src/` that rustdoc compiles examples from."""
    if not path.is_file() or source_root not in path.parents:
        return False
    rel = path.relative_to(source_root)
    return not (rel.parts[0] == "bin" or path.name == "main.rs" or skipped(rel))


def _doctest_sources(row: dict) -> Iterator[Path]:
    source_root = (REPO_ROOT / row["root"]).parent
    for rel_file in row["srcs"]:
        path = REPO_ROOT / rel_file
        if _is_documented_source(path, source_root):
            yield path


def doctest_controls() -> list[Control]:
    """Every rustdoc example in a library a `rust_doc_test` target runs, `compile_fail` ones included.

    A doctest's libtest name is `src/file.rs - item::path (line N)`, which is a shape the
    registry cannot join on without the line, so identity here is the `doc#` selector the
    test lane already uses: the ITEM the example documents. `compile_fail` is carried on
    the control so a census can refuse to count a compile refusal as behavioural evidence,
    which is ADR-MCPRE-068 §4.1's rule and not this module's to relax.

    Only a library some `rust_doc_test` runs: an example rustdoc never executes is prose in
    a code font, not a control.
    """
    out: list[Control] = []
    for _label, row in sorted(_rust_targets.table().items()):
        if row["kind"] != "rust_doc_test":
            continue
        source_root = (REPO_ROOT / row["root"]).parent
        for path in _doctest_sources(row):
            out.extend(_doctests_in(path, row["package"], _doc_module_path(path, source_root)))
    return out
