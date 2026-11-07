# SPDX-License-Identifier: Apache-2.0
"""The dependency set of a module's production half.

Opens a test region: tests legitimately `use super::*`. Both `#[cfg(test)]` and
`#[cfg(all(test, ...))]` open one, and a region CLOSES with the item its attribute introduces —
the same definition `scripts/module_size_gate.py` uses. Truncating at the first marker instead
would state "test code begins here and never ends", which Rust does not say: an inline
`#[cfg(test)]` helper may sit far above the test module, and production items may follow it.
"""

from __future__ import annotations

from collections.abc import Iterator

from _rust_source import production_view

from _lifecycle_purity.config import ALLOWED_STD_PATHS, CHILD_MOD, LOCAL_DECL, PATH_ROOT, USE_DECL

Body = list[tuple[int, str]]


def production_half(text: str) -> Body:
    """Every production line that carries code, 1-indexed, comments and literals blanked.

    Comments are dropped because the module's doc comments reference `crate::app` in prose
    and rustdoc links; literals because a path inside an error string is text. The gate is
    about code, and the test region is the owner's: `_rust_source` decides where it ends.
    """
    return production_view(text).numbered_code()


def child_modules(body: Body) -> list[str]:
    """The out-of-line child modules the production half declares."""
    return [match.group("name") for _, code in body if (match := CHILD_MOD.match(code))]


def _aliases(body: Body) -> Iterator[tuple[str, str]]:
    """Every `use source as alias;` of the production half."""
    for _, code in body:
        for match in USE_DECL.finditer(code):
            path = match.group("path").strip()
            if " as " in path:
                source, alias = (part.strip() for part in path.split(" as ", 1))
                yield source, alias


def _extends_locals(names: set[str], source: str, alias: str) -> bool:
    """Whether `alias` is a new local name: it renames a bare local `source`."""
    return "::" not in source and source in names and alias not in names


def local_names(text: str, body: Body) -> set[str]:
    """Names that resolve inside this module: declared types and child modules, plus
    self-alias targets.

    `use RuntimeEvent as E;` makes `E` local, because `RuntimeEvent` is local. An alias of
    something non-local is not: it is an import wearing a short name, which is exactly the
    case a spelling-based check would wave through.
    """
    names = {
        match.group("name")
        for line in text.splitlines()
        if (match := LOCAL_DECL.match(line))
    }
    names.update(child_modules(body))
    aliases = list(_aliases(body))
    # Fixed point: an alias chain (A as B, B as C) stays local only if it starts local.
    changed = True
    while changed:
        changed = False
        for source, alias in aliases:
            if _extends_locals(names, source, alias):
                names.add(alias)
                changed = True
    return names


def _allowed_std(head: str) -> bool:
    return any(head == allow or head.startswith(f"{allow}::") for allow in ALLOWED_STD_PATHS)


def _depends_inward(head: str, local: set[str]) -> bool:
    """Whether a `use` of `head` stays inside the module: a self-alias, a path rooted in a
    local name (`use RuntimeState::*` over its own variants), or an allowed std path."""
    self_alias = "::" not in head and head in local
    return self_alias or head.split("::", 1)[0] in local or _allowed_std(head)


def _use_findings(number: int, code: str, local: set[str]) -> list[str]:
    found: list[str] = []
    for match in USE_DECL.finditer(code):
        path = match.group("path").strip()
        if not _depends_inward(path.split(" as ")[0].strip(), local):
            found.append(f"{number}: imports `{path}`")
    return found


def _path_findings(number: int, code: str, local: set[str]) -> list[str]:
    found: list[str] = []
    for match in PATH_ROOT.finditer(code):
        root = match.group("root")
        if root in local or root in {"Self", "self"}:
            continue
        # A qualified path whose root is std: allowed only if the two-segment prefix
        # is on the list. `std::fmt::Formatter` yes; `std::sync::Mutex` no.
        segments = code[match.start() :].split("::")
        prefix = "::".join(segment.strip() for segment in segments[:2])
        if any(prefix.startswith(allow) for allow in ALLOWED_STD_PATHS):
            continue
        found.append(f"{number}: path into `{root}`")
    return found


def external_dependencies(text: str, child: bool = False) -> list[str]:
    """Every module-external name the production half depends on, as `line: what`.

    Empty list means the relation depends on nothing outside itself but the allowed
    standard-library paths. For a `child` module, `super` is its parent: inside the tree.
    """
    body = production_half(text)
    local = local_names(text, body)
    if child:
        local.add("super")
    found: list[str] = []
    for number, code in body:
        found += _use_findings(number, code, local)
        found += _path_findings(number, code, local)
    # One line can produce the same finding twice (a `use` and its path root); keep the
    # report readable without hiding distinct findings on the same line.
    return sorted(set(found), key=lambda entry: (int(entry.split(":", 1)[0]), entry))
