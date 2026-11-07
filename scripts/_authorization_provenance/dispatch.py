# SPDX-License-Identifier: Apache-2.0
"""Claims (7) and (8): dispatch is gated by the type, and no configuration promotes a reference evaluator."""

from __future__ import annotations

import re

from _authorization_provenance.config import (
    DISPATCH_BODY,
    DISPATCH_CAPABILITY,
    PLANE,
    PREPARE,
    RELEASE,
    SERVING,
    STAGES,
    VALIDATION,
)
from _authorization_provenance.rusttext import signature_re


def _prepare_problems(plane: str) -> list[str]:
    prepare = signature_re(PREPARE).search(plane)
    if prepare is not None and DISPATCH_BODY in prepare.group("params"):
        return []
    return [
        f"{PLANE}: `InnerPlane::{PREPARE}` no longer takes an `{DISPATCH_BODY}`. That "
        f"parameter IS the gate: a body typed `Vec<u8>` can be produced by any path, "
        f"including one that never asked a policy, and `{PREPARE}` is the only thing "
        f"that can transmit."
    ]


def _ready_problems(stages: str) -> list[str]:
    ready = signature_re("new").search(stages)
    if ready is not None and DISPATCH_CAPABILITY in ready.group("params"):
        return []
    return [
        f"{STAGES}: `ReadyForDispatch::new` no longer takes a `{DISPATCH_CAPABILITY}`. "
        f"The ready state must carry the capability `{PREPARE}` returned, or it can be "
        f"assembled from bytes again and the released body stops being what goes out."
    ]


def _producer_problems(authority: str) -> list[str]:
    producers = len(re.findall(r"\bfn\s+" + RELEASE + r"\s*\(", authority))
    if producers == 1:
        return []
    return [
        f"the authorization authority defines `{RELEASE}` {producers} time(s); expected "
        f"exactly 1. A second producer of `{DISPATCH_BODY}` is a second way to reach "
        f"the backend, and the type stops proving anything."
    ]


def _release_call_problems(serving: str) -> list[str]:
    calls = len(re.findall(r"\." + RELEASE + r"\s*\(", serving))
    if calls == 1:
        return []
    return [
        f"{SERVING}: calls `.{RELEASE}(` {calls} time(s); expected exactly 1. One "
        f"decision releases one body."
    ]


def check_dispatch(stages: str, authority: str, serving: str, plane: str) -> list[str]:
    """(7) — dispatch is gated by the type, not by source order."""
    return (
        _prepare_problems(plane)
        + _ready_problems(stages)
        + _producer_problems(authority)
        + _release_call_problems(serving)
    )


def check_validation(text: str) -> list[str]:
    """(8) — no configuration promotes a conformance evaluator to production authority."""
    if "AuthzKind::Reference" in text:
        return []
    return [
        f"{VALIDATION}: no longer refuses `--authz reference`. ADR-MCPRE-065 §7.2: a "
        f"reference/conformance evaluator may prove the boundary and must never become "
        f"the accepted production authorization authority."
    ]
