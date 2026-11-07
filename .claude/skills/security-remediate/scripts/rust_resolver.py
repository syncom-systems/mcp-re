"""Rust module-path resolution for the remediation dependency graph.

`targets(path)` is the set of tracked `.rs` files whose items the production part
of `path` names: every `crate::` / `super::` / `self::` / `<workspace crate>::`
path, `use` trees expanded, each resolved to the longest prefix that is a module
file, then through that module's `pub use` re-exports to the defining file.

An instrument with a stated reach: text, not name resolution. It cannot see a
glob import's individual names, a macro-generated path, or a trait method reached
through a value; a missed edge makes `related` smaller, never wrong.
"""
from __future__ import annotations

import os
import re

from rust_crates import CrateIndex
from rust_use_tree import USE, expand_use_tree, production_text, reexport_table

_MAX_HOPS = 4
_RELATIVE = ("super", "self")


class RustResolver:
    def __init__(self, root: str) -> None:
        self.root = root
        self.index = CrateIndex(root)
        heads = "|".join(["crate", "super", "self"] + [re.escape(c) for c in self.index.crates])
        self._path_re = re.compile(r"\b(?:%s)(?:::\w+)+" % heads)
        self._reexports: dict[str, dict[str, list[str]]] = {}

    def crate_of(self, path: str) -> str | None:
        return self.index.crate_of(path)

    def module_path(self, path: str) -> list[str]:
        return self.index.module_path(path)

    def _absolute(self, path: str, segs: list[str]) -> tuple[str, list[str]] | None:
        """(crate, absolute segments) for a path written inside `path`."""
        if not segs:
            return None
        own = self.index.crate_of(path)
        if segs[0] == "crate" and own:
            return own, segs[1:]
        if segs[0] in _RELATIVE and own:
            return own, self._relative(path, segs)
        if segs[0] in self.index.crates:
            return segs[0], segs[1:]
        # A 2018-edition path may start at a child module of the current one.
        return self._child_path(own, path, segs) if own else None

    def _relative(self, path: str, segs: list[str]) -> list[str]:
        """Walk the leading `super`/`self` segments up from `path`'s own module."""
        mod = self.index.module_path(path)
        i = 0
        while i < len(segs) and segs[i] in _RELATIVE:
            if segs[i] == "super":
                mod = mod[:-1]
            i += 1
        return mod + segs[i:]

    def _child_path(self, own: str, path: str, segs: list[str]) -> tuple[str, list[str]] | None:
        mod = self.index.module_path(path)
        if self.index.module_file(own, mod + [segs[0]]):
            return own, mod + segs
        return None

    def _module_reexports(self, file: str) -> dict[str, list[str]]:
        """item name -> the path its `pub use` points at, for one module file."""
        if file not in self._reexports:
            self._reexports[file] = reexport_table(production_text(self._read(file)))
        return self._reexports[file]

    def _read(self, path: str) -> str:
        with open(os.path.join(self.root, path), encoding="utf-8", errors="ignore") as fh:
            return fh.read()

    def _longest_module(self, crate: str, rest: list[str]) -> tuple[str, int] | None:
        """The module file named by the longest prefix of `rest`, and that prefix's length."""
        for n in range(len(rest), -1, -1):
            f = self.index.module_file(crate, rest[:n])
            if f:
                return f, n
        return None

    def _reexport_hop(self, file: str, rest: list[str], used: int) -> list[str] | None:
        """Where `file` re-exports the item that follows the module prefix, if it does."""
        if used >= len(rest):
            return None
        return self._module_reexports(file).get(rest[used])

    def resolve(self, path: str, segs: list[str]) -> str | None:
        ab = self._absolute(path, segs)
        if ab is None:
            return None
        crate, rest = ab
        file = None
        for _ in range(_MAX_HOPS):
            found = self._longest_module(crate, rest)
            if found is None:
                return None
            file, used = found
            hop = self._reexport_hop(file, rest, used)
            if not hop:
                return file
            nxt = self._absolute(file, hop)
            if nxt is None or nxt == (crate, rest):
                return file
            crate, rest = nxt
        return file

    def _scannable(self, path: str) -> bool:
        if not path.endswith(".rs") or self.index.crate_of(path) is None:
            return False
        return os.path.isfile(os.path.join(self.root, path))

    def _named_paths(self, src: str) -> list[list[str]]:
        """Every path `src` names: through `use` trees, then written out in full."""
        paths: list[list[str]] = []
        for m in USE.finditer(src):
            paths += expand_use_tree(m.group(2))
        paths += [m.group(0).split("::") for m in self._path_re.finditer(USE.sub("", src))]
        return paths

    def targets(self, path: str) -> set[str]:
        if not self._scannable(path):
            return set()
        resolved = (self.resolve(path, segs) for segs in self._named_paths(
            production_text(self._read(path))))
        return {f for f in resolved if f and f != path}
