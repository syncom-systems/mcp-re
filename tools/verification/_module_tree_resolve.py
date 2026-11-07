# SPDX-License-Identifier: Apache-2.0
"""Resolving declarations to files, rustc's way: which file each `mod x;` names, which files
a crate root reaches (`walk`), and the declarations that name each segment of a module path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from _module_tree_decl import Declaration, read_declarations

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


def _descend(
    here: Path, here_offset: str | None, enclosing: tuple[str, str | None]
) -> tuple[Path, None]:
    """Move into one enclosing inline module: under its `#[path]`, else under its name."""
    name, explicit = enclosing
    if explicit is not None:
        return here / explicit, None
    return (here / here_offset / name if here_offset else here / name), None


def _enclosing_location(
    decl: Declaration, directory: Path, offset: str | None
) -> tuple[Path, str | None]:
    """Where an inline module chain around `decl` moves the directory and the offset."""
    here, here_offset = directory, offset
    for enclosing in decl.enclosing:
        here, here_offset = _descend(here, here_offset, enclosing)
    return here, here_offset


def _resolve(decl: Declaration, here: Path, here_offset: str | None) -> Child:
    explicit = decl.path_attribute
    if explicit is not None:
        candidate = here / explicit
        return Child(decl, candidate if candidate.is_file() else None, True)
    base = here / here_offset if here_offset else here
    file_form, dir_form = base / f"{decl.name}.rs", base / decl.name / "mod.rs"
    if file_form.is_file():
        return Child(decl, file_form, False)
    if dir_form.is_file():
        return Child(decl, dir_form, True)
    return Child(decl, None, False)


def children(path: Path, *, mod_rs: bool) -> list[Child]:
    """Every `mod x;` in `path`, resolved as rustc resolves it.

    `mod_rs` is how `path` was loaded: True for a crate root, a `mod.rs` and a `#[path]`
    file, False for a file reached as `name.rs`.
    """
    directory = path.parent
    offset = None if mod_rs else path.stem
    return [
        _resolve(decl, *_enclosing_location(decl, directory, offset))
        for decl in read_declarations(path)
        if not decl.inline
    ]


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

    def visit(
        path: Path,
        module: tuple[str, ...],
        by: Path | None,
        decl: Declaration | None,
        mod_rs: bool,
        test: bool,
    ) -> None:
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


def _named(
    decls: list[Declaration], segment: str, inline: tuple[str, ...]
) -> Declaration | None:
    return next(
        (d for d in decls if d.name == segment and tuple(n for n, _ in d.enclosing) == inline),
        None,
    )


def _file_child(current: Path, mod_rs: bool, found: Declaration) -> Child | None:
    return next((c for c in children(current, mod_rs=mod_rs) if c.declaration == found), None)


def declaration_chain(root: Path, module: tuple[str, ...]) -> list[Declaration]:
    """The declarations that name each segment of `module`, from `root`, as far as they go.

    An inline module is followed inside its file; a file module moves to its file. The chain
    stops at the first segment no declaration names.
    """
    current, mod_rs = root, True
    inline: tuple[str, ...] = ()
    chain: list[Declaration] = []
    for segment in module:
        found = _named(read_declarations(current), segment, inline)
        if found is None:
            break
        chain.append(found)
        if found.inline:
            inline = inline + (segment,)
            continue
        child = _file_child(current, mod_rs, found)
        if child is None or child.file is None:
            break
        current, mod_rs, inline = child.file, child.mod_rs, ()
    return chain
