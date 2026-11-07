# SPDX-License-Identifier: Apache-2.0
"""SPDX license expressions: is some choice the expression offers made of allowed licenses only."""

from __future__ import annotations

import re


def tokens(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr.replace("/", " OR "))


class _Parser:
    """Recursive descent over `OR` of `AND` of atoms; an atom is a license, `license WITH
    exception`, or a parenthesised expression. Each atom is judged against the allow-list."""

    def __init__(self, expr: str, toks: list[str], allow: set[str]) -> None:
        self.expr = expr
        self.toks = toks
        self.allow = allow
        self.pos = 0

    def _next_is(self, word: str) -> bool:
        return self.pos < len(self.toks) and self.toks[self.pos] == word

    def _atom(self) -> bool:
        tok = self.toks[self.pos]
        self.pos += 1
        if tok == "(":
            return self._group()
        ident = tok.rstrip("+")
        if self._next_is("WITH"):
            exception = self.toks[self.pos + 1]
            self.pos += 2
            return f"{ident} WITH {exception}" in self.allow
        return ident in self.allow

    def _group(self) -> bool:
        value = self._disjunction()
        if not self._next_is(")"):
            raise ValueError(f"unbalanced SPDX expression {self.expr!r}")
        self.pos += 1
        return value

    def _conjunction(self) -> bool:
        value = self._atom()
        while self._next_is("AND"):
            self.pos += 1
            value = self._atom() and value
        return value

    def _disjunction(self) -> bool:
        value = self._conjunction()
        while self._next_is("OR"):
            self.pos += 1
            value = self._conjunction() or value
        return value

    def parse(self) -> bool:
        result = self._disjunction()
        if self.pos != len(self.toks):
            raise ValueError(f"trailing tokens in SPDX expression {self.expr!r}")
        return result


def license_allowed(expr: str, allow: set[str]) -> bool:
    """Whether some choice the expression offers is made of allowed licenses only."""
    toks = tokens(expr)
    if not toks:
        return False
    return _Parser(expr, toks, allow).parse()
