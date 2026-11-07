# SPDX-License-Identifier: Apache-2.0
"""Claim (4): the serving path decides exactly once."""

from __future__ import annotations

import re

from _authorization_provenance.config import POSTURE, POSTURE_VARIANTS, REGION_ASSEMBLY, SERVING
from _authorization_provenance.rusttext import body_of


def _count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text))


def _handle_problems(text: str) -> list[str]:
    handle = body_of(text, "handle")
    if handle is None:
        return [f"{SERVING}: `handle` not found. The assembly is where the regions are ordered."]
    ordered = _count(r"\b" + REGION_ASSEMBLY + r"\s*\(", handle)
    if ordered == 1:
        return []
    return [
        f"{SERVING}: `handle` calls `{REGION_ASSEMBLY}` {ordered} time(s); expected "
        f"exactly 1. The pre-admission region is where the decision is sequenced, "
        f"and an assembly that entered it twice would decide twice."
    ]


def _region_problems(text: str) -> list[str]:
    region = body_of(text, REGION_ASSEMBLY)
    if region is None:
        return [
            f"{SERVING}: `{REGION_ASSEMBLY}` not found. The region assembly is where the "
            f"decision is ordered against its predecessors."
        ]
    asked = _count(r"\bauthorization_stage\s*\(", region)
    if asked == 1:
        return []
    return [
        f"{SERVING}: `{REGION_ASSEMBLY}` calls `authorization_stage` {asked} "
        f"time(s); expected exactly 1. The decision is ordered against its "
        f"predecessors HERE — a call from anywhere else is a second one that has "
        f"not been sequenced behind admission."
    ]


def _stage_count_problems(text: str) -> list[str]:
    calls = _count(r"\bauthorization_stage\s*\(", text)
    # One definition plus one call site.
    if calls == 2:
        return []
    return [
        f"{SERVING}: names `authorization_stage` {calls} time(s); expected exactly 2 "
        f"(its definition and one call). None is a serving path that dispatches "
        f"without deciding; more is two decisions that happen to agree."
    ]


def _stage_problems(text: str) -> list[str]:
    stage = body_of(text, "authorization_stage")
    if stage is None:
        return [f"{SERVING}: `authorization_stage` not found."]
    if ".decide(" in stage:
        return []
    return [
        f"{SERVING}: `authorization_stage` no longer reaches `AuthorizationStage::"
        f"decide`. The serving file owns the ORDERING; a stage that decided here would "
        f"be a second authority over what a decision means."
    ]


def _posture_problems(text: str) -> list[str]:
    return [
        f"{SERVING}: names `{POSTURE}::{variant}` in production. The serving path "
        f"CARRIES the posture the stage returned and never states one. A synthesized "
        f"`NoPolicyConfigured` at the dispatch is a configured policy bypassed, and "
        f"no type can refuse it — the body it releases is indistinguishable."
        for variant in POSTURE_VARIANTS
        if f"{POSTURE}::{variant}" in text
    ]


def check_serving(text: str) -> list[str]:
    """(4) — the serving path decides exactly once.

    Three links, each exactly once, so no one of them can be satisfied by a second route:
    the assembly orders the pre-admission region once, that region asks for the decision
    once, and the stage reaches the authority that owns what a decision means.

    The call count is taken over the WHOLE serving path, not only inside the ordering
    function. Before the split it was scoped to `handle`'s body, so a second call elsewhere
    in the file was invisible; reading the path whole is what the region modules require and
    is strictly the stronger question.
    """
    return (
        _handle_problems(text)
        + _region_problems(text)
        + _stage_count_problems(text)
        + _stage_problems(text)
        + _posture_problems(text)
    )
