# SPDX-License-Identifier: Apache-2.0
"""Trailing-comment removal shared by the YAML reader and the shell reader."""

from __future__ import annotations


def _opens_quote(ch: str, prev: str, quote_after: str | None) -> bool:
    if ch not in "'\"":
        return False
    return quote_after is None or prev in quote_after


def _starts_comment(quote: str, ch: str, prev: str, comment_after: str) -> bool:
    return not quote and ch == "#" and prev in comment_after


def _next_quote(quote: str, ch: str, prev: str, quote_after: str | None) -> str:
    """The quote character still open after `ch`, or empty when none is."""
    if quote:
        return "" if ch == quote else quote
    return ch if _opens_quote(ch, prev, quote_after) else ""


def strip_comment(text: str, quote_after: str | None, comment_after: str) -> str:
    """`text` without a trailing `# comment` that sits outside quotes.

    `quote_after` names the characters a quote may follow to open one (`None`: any
    position), and `comment_after` the characters a `#` may follow to start a comment. The
    start of the text satisfies both.
    """
    quote = ""
    for i, ch in enumerate(text):
        prev = text[i - 1] if i else ""
        if _starts_comment(quote, ch, prev, comment_after):
            return text[:i].rstrip()
        quote = _next_quote(quote, ch, prev, quote_after)
    return text.rstrip()
