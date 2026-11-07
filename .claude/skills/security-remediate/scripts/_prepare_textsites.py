"""Text-classified use sites: the fallback for Rust and for non-Python files."""
from __future__ import annotations

import re

_RUST_COMMENT = re.compile(r"^\s*//")


def _kind(sym: str, text: str) -> str:
    """Text classification — the Rust fallback only; Python sites are read from the AST."""
    t = text.strip()
    if t.startswith(("use ", "pub use ")):
        return "import"
    if re.search(r"\bimpl\b.*\b%s\b\s+for\b" % re.escape(sym), t):
        return "subclass"
    if re.search(r"\b%s\s*(?:\{|::new\b|\()" % re.escape(sym), t):
        return "construct"
    return "ref"


def text_sites(sym: str, lines: list[str], skip_comments: bool) -> list[tuple[str, int]]:
    return [(_kind(sym, lines[i]), i + 1) for i, ln in enumerate(lines)
            if re.search(r"\b%s\b" % re.escape(sym), ln)
            and not (skip_comments and _RUST_COMMENT.match(ln))]
