# SPDX-License-Identifier: Apache-2.0
"""Measuring the production edges between the proxy's top-level modules."""

from __future__ import annotations

import re
from collections import defaultdict

from _module_map.config import SRC
from _rust_source import production_view


def code_only(text: str) -> str:
    """Production code with test items, comments and string literals neutralised.

    String literals are blanked because a `crate::x::Y` inside an error message is text,
    not a dependency. Comments are dropped because a rustdoc intra-doc link is a
    reference for the reader; counting one would reward deleting documentation.
    """
    return production_view(text).code()


def _qualified(name: str, src: str, known: set[str], found: dict[str, set[str]]) -> None:
    for mod, sym in re.findall(r"crate::([a-z0-9_]+)::([A-Za-z0-9_]+)", src):
        if mod in known and mod != name:
            found[mod].add(sym)


def _bare_imports(name: str, src: str, known: set[str], found: dict[str, set[str]]) -> None:
    for mod in re.findall(r"^\s*use\s+crate::([a-z0-9_]+)\s*;", src, re.M):
        if mod not in known or mod == name:
            continue
        found[mod].update(re.findall(rf"\b{mod}::([A-Za-z0-9_]+)", src))
        found.setdefault(mod, set())


def edges_for(name: str, src: str, known: set[str]) -> dict[str, set[str]]:
    """Production edges out of one module, as {target: {symbols}}.

    Both reference forms count: a qualified `crate::cli::DeploymentRequest`, and a bare
    `use crate::cli;` followed by `cli::DeploymentRequest`. Missing the second under-reports badly.
    """
    found: dict[str, set[str]] = defaultdict(set)
    _qualified(name, src, known, found)
    _bare_imports(name, src, known, found)
    return dict(found)


def build_map() -> tuple[dict[str, dict[str, set[str]]], set[str]]:
    modules = {p.stem for p in SRC.glob("*.rs")} - {"lib"}
    graph: dict[str, dict[str, set[str]]] = {}
    for path in sorted(SRC.glob("*.rs")):
        if path.stem == "lib":
            continue
        graph[path.stem] = edges_for(
            path.stem, code_only(path.read_text(errors="replace")), modules
        )
    return graph, modules
