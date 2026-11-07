# SPDX-License-Identifier: Apache-2.0
"""Lexing for the production view: blanking comments and literals while keeping line structure."""

from __future__ import annotations

import re

_IDENT = re.compile(r"[A-Za-z0-9_]")


def _blanked(chunk: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in chunk)


_BLOCK_TOKEN = re.compile(r"/\*|\*/")
_RAW_OPEN = re.compile(r'#*"')
_QUOTED_BODY = re.compile(r'(?:\\.|[^"\\])*"', re.S)


def _block_comment_end(text: str, i: int) -> int:
    """Index one past the (nesting) block comment that opens at `i`, or the end of the text."""
    depth = 0
    for token in _BLOCK_TOKEN.finditer(text, i):
        depth += 1 if token.group() == "/*" else -1
        if depth == 0:
            return token.end()
    return len(text)


def _preceded_by_identifier(text: str, i: int) -> bool:
    """True when the character before `i` continues an identifier — except a `b` that itself
    starts the token (`br"…"`)."""
    if i == 0 or not _IDENT.match(text[i - 1]):
        return False
    starts_byte_prefix = text[i - 1] == "b" and (i < 2 or not _IDENT.match(text[i - 2]))
    return not starts_byte_prefix


def _raw_string_here(text: str, i: int) -> bool:
    """True when the `r` at `i` opens a raw string rather than ending an identifier."""
    return not _preceded_by_identifier(text, i) and _RAW_OPEN.match(text, i + 1) is not None


def _byte_string_here(text: str, i: int) -> bool:
    """True when the `b` at `i` opens `b"…"`; `br"…"` is handled at its `r`."""
    return (not i or not _IDENT.match(text[i - 1])) and text.startswith('b"', i)


def _raw_string_end(text: str, r: int) -> int:
    """Index one past the raw string whose `r` is at `r`: it closes only at its own hash count."""
    j = r + 1
    while j < len(text) and text[j] == "#":
        j += 1
    close = '"' + "#" * (j - r - 1)
    end = text.find(close, j + 1)
    return len(text) if end < 0 else end + len(close)


def _string_end(text: str, i: int) -> int:
    """Index one past the string literal starting at `i`."""
    if text[i] == "b":
        i += 1
    if text[i] == "r":
        return _raw_string_end(text, i)
    body = _QUOTED_BODY.match(text, i + 1)
    return body.end() if body else len(text)


def _char_literal_end(text: str, i: int) -> int:
    """Index one past a char literal at `i`; `i + 1` when it is a lifetime."""
    if text.startswith("'\\", i):
        j = text.find("'", i + 2)
        return i + 1 if j < 0 else j + 1
    if i + 2 < len(text) and text[i + 2] == "'":
        return i + 3
    return i + 1


def _starts_string(text: str, i: int) -> bool:
    c = text[i]
    return c == '"' or (c == "r" and _raw_string_here(text, i)) or (c == "b" and _byte_string_here(text, i))


def _next_token(text: str, i: int) -> tuple[int, str | None]:
    """`(end, kind)` of the comment or literal starting at `i`, else `(i + 1, None)`."""
    pair = text[i:i + 2]
    if pair == "//":
        j = text.find("\n", i)
        return (len(text) if j < 0 else j), "comment"
    if pair == "/*":
        return _block_comment_end(text, i), "comment"
    if _starts_string(text, i):
        return _string_end(text, i), "literal"
    if text[i] == "'" and _char_literal_end(text, i) > i + 1:
        return _char_literal_end(text, i), "literal"
    return i + 1, None


def code_only(text: str, *, literals: bool = False) -> str:
    """`text` with comments blanked, and string and char literals blanked unless `literals`.

    Line structure and columns are preserved. Rust block comments nest; a raw string
    `r#"…"#` closes only at its own hash count; a `'` that is not a char literal is a
    lifetime and stays.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        end, kind = _next_token(text, i)
        chunk = text[i:end]
        out.append(chunk if kind is None or (kind == "literal" and literals) else _blanked(chunk))
        i = end
    return "".join(out)
