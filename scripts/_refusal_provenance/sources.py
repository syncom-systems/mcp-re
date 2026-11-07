# SPDX-License-Identifier: Apache-2.0
"""Reading production Rust: units, owner subtrees, the workspace walk and brace-matched bodies."""

from __future__ import annotations

import re

from _rust_source import crate_sources, production_view

from _refusal_provenance.config import REPO


def workspace_rust_files() -> list[str]:
    """Every SHIPPED `.rs` path in the workspace: any Rust file under a crate's `src/`.

    The scope of the two whole-workspace absence claims — no `From<PolicyError>` route into
    the Core taxonomy, and no undeclared pre-exchange refusal site. Every crate, because the
    point of both is that the shape exists NOWHERE, and restricting the scan to the files
    that look relevant is how a gate stops covering its subject.

    `src/` is the boundary, and it is a MEASUREMENT rather than an exemption: a file outside
    it is compiled into no library and no binary that serves, so it cannot be a production
    refusal site or a production conversion. The distinction is load-bearing — the battery
    that measures clause 12 necessarily NAMES the mint it forbids, and a walk that counted
    a test file's string constant as a call site would fail on its own control. The
    exemption is visible rather than silent: `main` prints how many files were examined, and
    a scope that collapsed to nothing shows as a number, not as an OK.
    """
    return [
        str(p.relative_to(REPO))
        for p in crate_sources(REPO)
        if "src" in p.relative_to(REPO).parts
    ]


def read(rel: str, overrides: dict[str, str] | None = None) -> str:
    """The production half of `rel`, or a loud failure.

    A gate whose input has moved must say so rather than traceback or, worse, quietly examine
    nothing: an empty scope printing OK is how a control stops covering its subject.
    """
    if overrides and rel in overrides:
        return production_view(overrides[rel]).text()
    path = REPO / rel
    if not path.is_file():
        raise SystemExit(
            f"refusal-provenance gate: FAIL — {rel} is not there. The gate's scope has moved; "
            f"fix the scope rather than the symptom."
        )
    return production_view(path).text()


def read_unit(rel: str, overrides: dict[str, str] | None) -> str:
    """One unit's production source: a file, or an owner subtree read whole.

    Production halves are taken per member before joining, so one file's unterminated test
    region cannot swallow the next file's production code.
    """
    if overrides and rel in overrides:
        return production_view(overrides[rel]).text()
    target = REPO / rel
    if target.is_file():
        return read(rel, overrides)
    members = crate_sources(target)
    if not members:
        raise SystemExit(f"{rel}: an owner subtree with no Rust source is not measurable")
    return "\n".join(production_view(m).text() for m in members)


def _braced(src: str, start: int) -> str:
    """The text from the `{` at `start` through its matching `}`, or to the end if it never closes."""
    depth = 0
    for i in range(start, len(src)):
        depth += (src[i] == "{") - (src[i] == "}")
        if depth == 0:
            return src[start : i + 1]
    return src[start:]


def body_of(src: str, fn: str) -> str:
    """The body of `fn`, brace-matched from its signature."""
    m = re.search(rf"fn\s+{re.escape(fn)}\s*[(<]", src)
    if not m:
        return ""
    return _braced(src, src.index("{", m.start()))


def body_of_variant(src: str, variant: str) -> str:
    """The brace-matched body of enum variant `variant`, or `""`."""
    m = re.search(rf"^\s{{4}}{re.escape(variant)}\s*\{{", src, re.M)
    if not m:
        return ""
    return _braced(src, src.index("{", m.start()))
