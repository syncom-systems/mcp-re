# SPDX-License-Identifier: Apache-2.0
"""Cargo's version requirement semantics, as RustSec's `patched`/`unaffected` lists use them."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

Version = tuple[int, int, int, tuple]
#: One primitive comparison: (operator, full version).
Primitive = tuple[str, Version]


def parse_version(text: str) -> Version:
    core, _, pre = text.split("+", 1)[0].partition("-")
    major, minor, patch = (int(p) for p in core.split("."))
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ()
    return major, minor, patch, ids


def version_key(v: Version) -> tuple:
    # A release outranks every pre-release of the same core.
    return v[:3] + ((1,) if not v[3] else (0, v[3]))


def _full(a: int, b: int, c: int, pre: str = "") -> Version:
    return parse_version(f"{a}.{b}.{c}" + (f"-{pre}" if pre else ""))


@dataclass(frozen=True)
class _Spec:
    """A comparator's version text: how many numeric parts it names, and their values."""

    n: int
    major: int
    minor: int
    patch: int
    pre: str

    def exact(self) -> Version:
        return _full(self.major, self.minor, self.patch, self.pre)

    def next_partial(self) -> Version:
        """The first version past a partial `major` or `major.minor`."""
        return _full(self.major + 1, 0, 0) if self.n == 1 else _full(self.major, self.minor + 1, 0)


def _spec(text: str) -> _Spec:
    parts = text.split("-", 1)[0].split(".")
    pre = text.split("-", 1)[1] if "-" in text else ""
    nums = [int(p) for p in parts if p not in ("*", "x", "X")]
    major, minor, patch = (nums + [0, 0, 0])[:3]
    return _Spec(len(nums), major, minor, patch, pre)


def _equal(s: _Spec) -> list[Primitive]:
    if s.n == 3:
        return [("=", s.exact())]
    return [(">=", _full(s.major, s.minor, 0)), ("<", s.next_partial())]


def _tilde(s: _Spec) -> list[Primitive]:
    if s.n < 3:
        return _equal(s)
    return [(">=", s.exact()), ("<", _full(s.major, s.minor + 1, 0))]


def _caret(s: _Spec) -> list[Primitive]:
    lower = (">=", s.exact())
    if s.major > 0 or s.n == 1:
        return [lower, ("<", _full(s.major + 1, 0, 0))]
    if s.minor > 0 or s.n == 2:
        return [lower, ("<", _full(0, s.minor + 1, 0))]
    return [lower, ("<", _full(0, 0, s.patch + 1))]


def _greater(s: _Spec) -> list[Primitive]:
    if s.n == 3:
        return [(">", s.exact())]
    return [(">=", s.next_partial())]


def _at_least(s: _Spec) -> list[Primitive]:
    return [(">=", s.exact())]


def _less(s: _Spec) -> list[Primitive]:
    return [("<", s.exact())]


def _at_most(s: _Spec) -> list[Primitive]:
    if s.n == 3:
        return [("<=", s.exact())]
    return [("<", s.next_partial())]


_COMPARATORS: dict[str, Callable[[_Spec], list[Primitive]]] = {
    "=": _equal, "~": _tilde, "^": _caret, ">": _greater, ">=": _at_least, "<": _less, "<=": _at_most,
}


def bounds(op: str, text: str) -> list[Primitive]:
    """One comparator as a conjunction of (op, full version) primitives."""
    spec = _spec(text)
    if op == "*" or spec.n == 0:
        return []
    comparator = _COMPARATORS.get(op)
    if comparator is None:
        raise ValueError(f"unknown comparator {op!r}")
    return comparator(spec)


def _primitives(req: str) -> list[Primitive]:
    prims: list[Primitive] = []
    for comp in (c.strip() for c in req.split(",") if c.strip()):
        m = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?\s*(\S+)", comp)
        if not m:
            raise ValueError(f"unparseable requirement {req!r}")
        text = m.group(2)
        prims += bounds(m.group(1) or ("*" if text == "*" else "^"), text)
    return prims


def _satisfies(v: Version, op: str, bound: Version) -> bool:
    a, b = version_key(v), version_key(bound)
    return {"=": a == b, ">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]


def matches(req: str, version: str) -> bool:
    v = parse_version(version)
    prims = _primitives(req)
    if not all(_satisfies(v, op, bound) for op, bound in prims):
        return False
    # A pre-release matches only a comparator naming a pre-release of the same core.
    return not v[3] or any(bound[3] and bound[:3] == v[:3] for _, bound in prims)
