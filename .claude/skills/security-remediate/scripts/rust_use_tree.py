"""Rust source text helpers for `rust_resolver`: production text and `use` trees."""
from __future__ import annotations

import re

_TEST_REGION = re.compile(r"^#\[cfg\((?:all\()?test", re.M)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_ALIAS = re.compile(r"\s+as\s+\w+")

#: A `use` item; group 1 is its `pub` prefix when it is a re-export, group 2 its tree.
USE = re.compile(r"\b(pub(?:\([^)]*\))?\s+)?use\s+([^;]+);")


def production_text(src: str) -> str:
    """`src` before its first test region, with comments and string contents removed."""
    m = _TEST_REGION.search(src)
    body = src[:m.start()] if m else src
    return _STRING.sub('""', _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", body)))


def expand_use_tree(tree: str) -> list[list[str]]:
    """`a::{b, c::{d, e}}` -> [[a,b], [a,c,d], [a,c,e]]; `self` and `*` stop a path."""
    return _paths([], re.sub(r"\s+", "", _ALIAS.sub("", tree)))


def _split_top(s: str) -> list[str]:
    """Split on the commas that sit outside every brace pair."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(s):
        depth += (ch == "{") - (ch == "}")
        if ch == "," and depth == 0:
            parts.append(s[start:i])
            start = i + 1
    if s[start:]:
        parts.append(s[start:])
    return parts


def _paths(prefix: list[str], s: str) -> list[list[str]]:
    brace = s.find("{")
    if brace == -1:
        path = prefix + [x for x in s.split("::") if x and x not in ("self", "*")]
        return [path] if path else []
    head = [x for x in s[:brace].split("::") if x]
    inner = s[brace + 1:s.rfind("}")]
    return [p for part in _split_top(inner) for p in _paths(prefix + head, part)]


def reexport_table(src: str) -> dict[str, list[str]]:
    """item name -> the path its `pub use` points at, for production text `src`."""
    trees = (m.group(2) for m in USE.finditer(src) if m.group(1))
    return {segs[-1]: segs for tree in trees for segs in expand_use_tree(tree)}
