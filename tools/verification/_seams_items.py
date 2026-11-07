# SPDX-License-Identifier: Apache-2.0
"""The ITEM a seam sits on, and the stable `<path>#<qualified item>` key that names it.

One forward pass per file decides every item's qualifier (the `impl`/`mod` blocks open above
it); a seam is then answered by the first declaration at or after it.
"""

from __future__ import annotations

import re
from bisect import bisect_left

from _seams_patterns import code_of

#: `assume_specification[ <path> ]` names its item INSIDE the brackets, so the seam and the
#: item it trusts sit on one line. Bracket-balanced rather than non-greedy: `<[T]>::split_last`
#: contains a `]` of its own, and a non-greedy match truncates it to `<[T` — a site key that
#: silently merges two different standard-library seams.
_ASSUME_SPEC = re.compile(r"\bassume_specification\b")

#: An item declaration, in the forms Verus and Rust both use. `uninterp`, `spec`, `proof`,
#: `open`, `closed`, `tracked` and `ghost` are Verus modifiers; the rest are Rust's.
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+"
    r"|uninterp\s+|spec\s+|proof\s+|exec\s+|open\s+|closed\s+|tracked\s+|ghost\s+)*"
    r"(?:fn|struct|enum|union|trait|type|mod)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

#: The block forms that QUALIFY the items inside them. `impl Trait for Type` and `impl Type`
#: both qualify by the TYPE: two `actor_id` methods in two impl blocks of one file are two
#: seams, and a key that could not tell them apart would let one registration license both.
_IMPL = re.compile(r"^\s*(?:unsafe\s+)?impl\b(?P<head>[^{]*)")
_MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")

#: String and char literals, removed before braces are counted. A `{` inside a literal does
#: not open a block, and a qualifier stack that believed it would mis-attribute every item
#: after it.
_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])'")


def _impl_type(head: str) -> str | None:
    """The TYPE an `impl` block qualifies, from the text between `impl` and `{`."""
    text = head.split(" for ")[-1] if " for " in head else head
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<.*)?$", text.strip().rstrip("<"))
    if match:
        return match.group(1)
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    return match.group(1) if match else None


def _brackets(text: str) -> tuple[int, int]:
    """`(square balance, brace balance)` of `text`, literals removed."""
    bare = _LITERAL.sub("", text)
    return (
        bare.count("[") - bare.count("]"),
        bare.count("{") - bare.count("}"),
    )

def _block_name(code: str) -> str | None:
    """The qualifier an `impl` or `mod` head contributes, or None for any other block."""
    impl_match = _IMPL.match(code)
    if impl_match:
        return _impl_type(impl_match.group("head"))
    mod_match = _MOD.match(code)
    return mod_match.group("name") if mod_match else None


def declared_items(lines: list[str]) -> list[tuple[int, str]]:
    """Every item declaration in `lines`, as `(1-based line, qualified name)`, in order.

    ONE forward pass per file, and that is a correctness property rather than a speed one:
    the qualifier of an item is decided by the blocks open above it, so a per-seam walk from
    the top of the file re-derives the same stack once per seam. Over the whole scan — every
    `.rs`, `.lean` and `.v` file a unit declares plus the whole `verification/` tree — that
    is quadratic in the size of the files with the most seams, which are exactly the
    specification files.

    Braces are counted over code with comments and literals removed, and only `impl`/`mod`
    heads contribute a qualifier; every other block adds depth without a name, so
    `verus!{ ... }` and ordinary function bodies do not qualify what they contain.
    """
    items: list[tuple[int, str]] = []
    stack: list[tuple[int, str | None]] = []
    depth = 0
    for index, line in enumerate(lines):
        code = code_of(line)
        match = _ITEM.match(code)
        if match:
            qualifiers = [name for _, name in stack if name]
            items.append((index + 1, "::".join([*qualifiers, match.group("name")])))
        opened = _brackets(code)[1]
        if opened > 0:
            stack.append((depth, _block_name(code)))
        depth += opened
        while stack and depth <= stack[-1][0]:
            stack.pop()
    return items


def item_at(
    lines: list[str], lineno: int, items: list[tuple[int, str]] | None = None
) -> str | None:
    """The ITEM a seam on `lineno` (1-based) sits on, qualified by its enclosing block.

    Two shapes, because Verus writes the seam two ways. `assume_specification[ X ]` names
    the trusted symbol in its own brackets and is answered from that line. Every other
    mechanism is an attribute or a modifier on a following item, so the answer is the FIRST
    declaration at or after the seam — never backwards from the item, and never a line
    number.

    A line number is what a registry must not be keyed on: adding a comment above a seam
    would move every key below it, and a registry that goes stale on formatting is one people
    regenerate without reading. The item's NAME is what the trust decision was about.

    The qualifier matters as much as the name. `mcp-re-http-profile/src/block.rs` declares
    `actor_id` twice, in `impl ActorIdentity` and in `impl ResolvedActor`; an unqualified key
    would make them one site, and registering either would license both.

    `items` is `declared_items(lines)`, passed in by a caller answering for several seams in
    one file so the pass is performed once.

    `None` where no declaration follows — a seam that cannot be named cannot be registered,
    and the gate says so rather than inventing a key.
    """
    line = code_of(lines[lineno - 1]) if 0 < lineno <= len(lines) else ""
    if _ASSUME_SPEC.search(line):
        return _assume_spec_item(lines, lineno)
    if items is None:
        items = declared_items(lines)
    index = bisect_left(items, (lineno, ""))
    return items[index][1] if index < len(items) else None


def _closing_bracket(text: str, start: int) -> int | None:
    """The offset of the `]` that balances the `[` at `start`, or None when it is unclosed."""
    depth = 0
    for offset, char in enumerate(text[start:], start=start):
        depth += (char == "[") - (char == "]")
        if depth == 0:
            return offset
    return None


def _assume_spec_item(lines: list[str], lineno: int) -> str | None:
    """The symbol inside `assume_specification[ ... ]`, across line breaks if it wraps."""
    text = ""
    for index in range(lineno - 1, min(lineno + 8, len(lines))):
        text += code_of(lines[index])
        start = text.find("[", text.find("assume_specification"))
        if start < 0:
            continue
        end = _closing_bracket(text, start)
        if end is not None:
            return text[start + 1 : end].strip() or None
    return None


def site_key(
    relative_path: str,
    lines: list[str],
    lineno: int,
    items: list[tuple[int, str]] | None = None,
) -> str | None:
    """`<path>#<qualified item>` — the stable identity of one trusted seam."""
    item = item_at(lines, lineno, items)
    return f"{relative_path}#{item}" if item else None
