# SPDX-License-Identifier: Apache-2.0
"""Clauses 1-4 and 6: a refusal carries a cause, the cause algebra is closed and exhaustive."""

from __future__ import annotations

import re

from _refusal_provenance.sources import body_of


def _cause_field_problems(refusal: str) -> list[str]:
    """1. a cause, not a token."""
    problems: list[str] = []
    if not re.search(r"cause:\s*RefusalCause", refusal):
        problems.append("`Refusal` must carry a `cause: RefusalCause`")
    if re.search(r"^\s*(pub\(crate\)\s+)?wire_code:\s*&'static str", refusal, re.M):
        problems.append(
            "`Refusal` carries a rendered `wire_code` FIELD — that is the Slice 0 defect"
        )
    return problems


def _arm_problems(refusal: str) -> list[str]:
    """2. closed over exactly two authorities."""
    arms = set(re.findall(r"^\s{4}(Core|Authorization)\(", refusal, re.M))
    if arms == {"Core", "Authorization"}:
        return []
    return [f"`RefusalCause` arms must be exactly Core+Authorization, found {arms}"]


def _stage_problems(serving: str) -> list[str]:
    """3. POISON PILL 1 — the authorization stage hands its refusal over whole."""
    stage = body_of(serving, "authorization_stage")
    if not stage:
        return ["`authorization_stage` not found in the serving path"]
    if ".wire_code()" not in stage:
        return []
    return [
        "`authorization_stage` renders its refusal — the typed provenance dies at the "
        "stage boundary (ADR-MCPRE-066 Slice 0 poison pill 1)"
    ]


def _constructor_problems(serving: str) -> list[str]:
    """4. no token rendered into a Refusal constructor."""
    problems: list[str] = []
    constructors = list(re.finditer(r"\bRefusal::(new)\(", serving))
    if not constructors:
        problems.append("no `Refusal::new(` call site in the serving path — check 4 measures nothing")
    for m in constructors:
        head = serving[m.end() : m.end() + 200].split(")")[0]
        if ".wire_code()" in head or re.search(r'"\s*mcp-re\.', head):
            problems.append(
                f"a `Refusal::{m.group(1)}` call site renders a token instead of passing a cause"
            )
    return problems


def cause_problems(refusal: str, serving: str) -> list[str]:
    """Clauses 1-4, in order."""
    return (
        _cause_field_problems(refusal)
        + _arm_problems(refusal)
        + _stage_problems(serving)
        + _constructor_problems(serving)
    )


def wildcard_problems(refusal: str) -> list[str]:
    """6. the cause algebra is exhaustive by construction."""
    if not re.search(r"^\s*_\s*=>", refusal, re.M):
        return []
    return [
        "`refusal/` has a wildcard arm — a new authority or Core producer would inherit a "
        "verdict instead of naming one"
    ]
