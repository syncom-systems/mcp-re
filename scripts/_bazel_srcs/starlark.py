# SPDX-License-Identifier: Apache-2.0
"""Delimiter-balanced reading of the Starlark and Rust text the gate inspects."""

from __future__ import annotations

import re

from _bazel_srcs.config import GUARD


def balanced(text: str, start: int, opener: str, closer: str) -> str:
    """The text from `start` (at `opener`) through its matching `closer`, inclusive."""
    depth = 0
    for i in range(start, len(text)):
        depth += (text[i] == opener) - (text[i] == closer)
        if depth == 0 and text[i] == closer:
            return text[start : i + 1]
    return text[start:]


def attribute_value(text: str, start: int) -> str:
    """The text of one Starlark attribute value beginning at `start`.

    Delimiter-balanced, so a value spanning several lines — `glob([...]) + [...]` — is read
    whole and the next attribute is not read at all.
    """
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if depth == 0 and ch in ")]},":
            return text[start:i]
        depth += (ch in "([{") - (ch in ")]}")
    return text[start:]


def rust_slice_const(text: str, name: str) -> str:
    """The body of `const NAME: &[…] = &[ … ];` in a Rust source."""
    match = re.search(r"\bconst\s+" + name + r"\s*:[^=]*=\s*&\[", text)
    if match is None:
        raise SystemExit(f"bazel srcs gate: {GUARD} declares no `{name}` — the hand list moved")
    return balanced(text, match.end() - 1, "[", "]")


def first_strings(body: str) -> list[str]:
    """The first string of every tuple in a slice of tuples."""
    return re.findall(r'\(\s*"([^"]+)"\s*,', body)


def quoted_strings(body: str) -> list[str]:
    return re.findall(r'"([^"]+)"', body)


def _srcs_value(rule: str) -> str:
    srcs = re.search(r"\bsrcs\s*=\s*", rule)
    return attribute_value(rule, srcs.end()).strip() if srcs else ""


def _is_plain_glob(value: str) -> bool:
    return value.startswith("glob(") and balanced(value, value.index("("), "(", ")") == value[4:]


def guard_patterns(build_text: str) -> tuple[list[str], list[str]]:
    """The include and exclude patterns of a package's `guard_src_files` glob, or none.

    Only `srcs = glob([...])`, with or without `exclude = [...]`, is read. Any other `srcs`
    shape raises `ValueError`: a pattern read from the wrong list would mark an excluded file
    as carried.
    """
    match = re.search(r'name\s*=\s*"guard_src_files"', build_text)
    if match is None:
        return [], []
    rule = balanced(build_text, build_text.rfind("(", 0, match.start()), "(", ")")
    value = _srcs_value(rule)
    if not _is_plain_glob(value):
        raise ValueError(f"guard_src_files srcs this gate does not read: {value!r}")
    call = value[5:-1]
    include = balanced(call, call.index("["), "[", "]")
    rest = call[call.index("[") + len(include) :]
    exclude_at = re.search(r"\bexclude\s*=\s*\[", rest)
    exclude = balanced(rest, exclude_at.end() - 1, "[", "]") if exclude_at else "[]"
    if re.sub(r"\bexclude\s*=\s*\[[^\]]*\]", "", rest).strip(" ,\n") != "":
        raise ValueError(f"guard_src_files glob arguments this gate does not read: {value!r}")
    return quoted_strings(include), quoted_strings(exclude)
