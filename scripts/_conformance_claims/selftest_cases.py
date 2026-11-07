# SPDX-License-Identifier: Apache-2.0
"""The selftest's fixtures: a guide, a BUILD file, a manifest and the failure it must raise."""

from __future__ import annotations

from typing import NamedTuple

from _conformance_claims.config import BEGIN, END, VECTORS_ROOT


class Case(NamedTuple):
    label: str
    guide: str
    build: str
    manifest: str
    expected: str


def _guide(rows: str) -> str:
    return (
        f"prose\n\n{BEGIN}\n\n| Category | Corpus | Harness targets |\n| --- | --- | --- |\n"
        f"{rows}\n{END}\n"
    )


def _build(*blocks: str) -> str:
    return "\n".join(f"nt_rust_test(\n{b}\n)" for b in blocks)


def _alpha(corpus: str = "alpha", target: str = "alpha_test") -> str:
    """The guide whose single row claims `corpus` and names `target` as its harness."""
    return _guide(
        f"| Alpha | `{VECTORS_ROOT}/{corpus}/` | `//mcp-re-conformance:{target}` |"
    )


def _alpha_test(data: str = "alpha", srcs: str | None = None) -> str:
    """The BUILD file declaring `alpha_test`, reaching `data` and optionally with `srcs`."""
    lines = ['    name = "alpha_test",']
    if srcs:
        lines.append(f'    srcs = ["{srcs}"],')
    lines.append(f'    data = glob(["tests/vectors/{data}/**"]),')
    return _build("\n".join(lines))


PLAIN = '{"fixtures": []}'
DIGESTED = '{"fixtures": [], "corpus_digest": "deadbeef"}'

CASES: tuple[Case, ...] = (
    Case(
        "a category with a corpus and a reaching harness passes",
        _alpha(),
        _alpha_test(),
        PLAIN,
        "",
    ),
    Case(
        "a category whose corpus does not exist",
        _alpha(corpus="ghost"),
        _alpha_test(),
        PLAIN,
        "does not exist",
    ),
    Case(
        "a category whose harness is not a declared target",
        _alpha(target="ghost_test"),
        _alpha_test(),
        PLAIN,
        "is not declared",
    ),
    Case(
        "a declared harness that never reaches the corpus",
        _alpha(),
        _alpha_test(data="other"),
        PLAIN,
        "does not execute it",
    ),
    Case(
        "a published corpus_digest no reaching harness recomputes",
        _alpha(),
        _alpha_test(srcs="tests/alpha_test.rs"),
        DIGESTED,
        "reads as a guarantee",
    ),
    Case(
        "a published corpus_digest a reaching harness does recompute",
        _alpha(),
        _alpha_test(srcs="tests/pinning_test.rs"),
        DIGESTED,
        "",
    ),
    Case(
        "a corpus the table does not advertise",
        _alpha(),
        _alpha_test(),
        PLAIN,
        "does not advertise",
    ),
    Case(
        "an empty table is refused rather than passed",
        f"prose\n\n{BEGIN}\n\n{END}\n",
        _alpha_test(),
        PLAIN,
        "no rows",
    ),
)
