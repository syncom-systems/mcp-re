# SPDX-License-Identifier: Apache-2.0
"""Reading Rust source text: comment-blanking, signatures, function bodies and struct fields."""

from __future__ import annotations

import re

from _rust_source import code_only


def without_comments(text: str) -> str:
    """`text` with comments blanked and literals kept. The claim is about the ROUTE, and a
    header name on the route is a string literal, so literals stay."""
    return code_only(text, literals=True)


def signature_re(name: str) -> re.Pattern:
    """`fn <name>( .. ) -> ..` up to the opening brace, with or without a generic or
    lifetime parameter list after the name."""
    return re.compile(
        r"fn\s+" + name + r"\s*(?:<[^{(]*?>)?\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S
    )


def _braced(text: str, start: int) -> str | None:
    """The text from the `{` at `start` through its matching `}`, or None if it never closes."""
    depth = 0
    for offset in range(start, len(text)):
        depth += (text[offset] == "{") - (text[offset] == "}")
        if depth == 0 and text[offset] == "}":
            return text[start : offset + 1]
    return None


def body_of(text: str, name: str) -> str | None:
    """The body of `name`, or None if it is not defined here."""
    match = signature_re(name).search(text)
    if match is None:
        return None
    return _braced(text, match.end() - 1)


def struct_body(text: str, name: str) -> str | None:
    """The field block of `struct <name> { .. }`, or None."""
    match = re.search(r"\bstruct\s+" + name + r"\b[^{;]*\{", text)
    if match is None:
        return None
    return _braced(text, match.end() - 1)
