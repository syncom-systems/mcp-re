# SPDX-License-Identifier: Apache-2.0
"""Claims (1), (2), (3), (5), (6) and (10): the authorization authority's own shape."""

from __future__ import annotations

import re

from _authorization_provenance.config import (
    FORBIDDEN_PARAM,
    LINKS,
    POSTURE,
    POSTURE_SITES,
    POSTURE_VARIANTS,
    RAW_PEER_ROUTE,
    SEALED,
    TRANSPORT_HINTS,
)
from _authorization_provenance.rusttext import body_of, signature_re, struct_body, without_comments


def _vocabulary_problems(sources: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for path, text in sources.items():
        code = without_comments(text)
        problems += [
            f"{path}: names `{name}` in production. Peer identity reaches "
            f"authorization as the ADR-MCPRE-064 binding or not at all; "
            f"reconstructing it here is what ADR-MCPRE-065 §3 forbids."
            for name in RAW_PEER_ROUTE
            if name in code
        ]
        problems += [
            f"{path}: names `{name}` in production. LAW A-1: the action coordinate "
            f"comes from the SIGNED BODY, and authorization correctness must not "
            f"depend on the MCP transport contract being enforced."
            for name in TRANSPORT_HINTS
            if name in code
        ]
    return problems


def _link_problem(sources: dict[str, str], filename: str, fn: str, must_reach: str) -> str | None:
    source = next(
        (without_comments(t) for path, t in sources.items() if path.endswith("/" + filename)),
        None,
    )
    if source is None:
        return (
            f"{filename}: no longer part of the authorization authority. A link this "
            f"gate cannot locate is a link it is not measuring."
        )
    body = body_of(source, fn)
    if body is None:
        return f"{filename}: `{fn}` not found."
    if must_reach in body:
        return None
    return (
        f"{filename}::{fn}: no longer reaches `{must_reach}`. The link is the "
        f"proof; without it the function answers from somewhere this gate cannot see."
    )


def _link_problems(sources: dict[str, str]) -> list[str]:
    found = [_link_problem(sources, *link) for link in LINKS]
    return [problem for problem in found if problem is not None]


def _authorize_problems(joined: str) -> list[str]:
    match = signature_re("authorize").search(joined)
    if match is None:
        return [
            "authorize: not found in the authorization authority. The decision has one "
            "operation, and a gate that cannot find it is measuring nothing."
        ]
    offending = sorted(set(FORBIDDEN_PARAM.findall(match.group("params"))))
    if not offending:
        return []
    return [
        f"authorize: parameter list admits {offending}. The enforcement mechanism "
        f"for Law A-1 and for §3 is the ABSENCE of a parameter through which a "
        f"header, a certificate or a rival identity could enter."
    ]


def _sealed_problem(joined: str, name: str) -> str | None:
    fields = struct_body(joined, name)
    if fields is None:
        return (
            f"{name}: no longer defined in the authorization authority. A sealed "
            f"product that moved out from under its gate is unsealed."
        )
    if re.search(r"^\s*pub(\s|\()", fields, re.M):
        return (
            f"{name}: has a `pub` field. The representation is private to its module, "
            f"which is the only in-crate seal there is: a public field lets a caller "
            f"assemble the product from parts nobody verified."
        )
    return None


def _sealed_problems(joined: str) -> list[str]:
    found = [_sealed_problem(joined, name) for name in SEALED]
    return [problem for problem in found if problem is not None]


def check_posture_producers(sources: dict[str, str]) -> list[str]:
    """(10) — the posture that claims nothing has one producer."""
    problems: list[str] = []
    for path, text in sources.items():
        if path.endswith(POSTURE_SITES):
            continue
        code = without_comments(text)
        problems += [
            f"{path}: names `{POSTURE}::{variant}` in production. The posture is "
            f"built in `decide.rs` and projected by `posture.rs`; a third site is "
            f"either a second producer — and `NoPolicyConfigured` released at the "
            f"dispatch is a configured policy bypassed — or a consumer "
            f"destructuring what it should be asking for."
            for variant in POSTURE_VARIANTS
            if f"{POSTURE}::{variant}" in code
        ]
    return problems


def check_authority(sources: dict[str, str]) -> list[str]:
    """(1), (2), (3), (5), (6) over the authorization authority."""
    joined = without_comments("\n".join(sources.values()))
    return (
        _vocabulary_problems(sources)
        + _link_problems(sources)
        + _authorize_problems(joined)
        + _sealed_problems(joined)
        + check_posture_producers(sources)
    )
