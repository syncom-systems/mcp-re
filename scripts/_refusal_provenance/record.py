# SPDX-License-Identifier: Apache-2.0
"""Clauses 7-11: the record states each authority's outcome, and no token is rendered into it."""

from __future__ import annotations

import re

from _refusal_provenance.config import CORE_AUDIT, RECORD
from _refusal_provenance.sources import body_of_variant


def _optional_facet_problems(record: str) -> list[str]:
    if "Option<AuthorizationFacet>" not in record:
        return []
    return [
        f"{RECORD}: the authorization facet is optional — an absent facet then means both "
        f"'no policy' and 'legacy record' (ADR-MCPRE-066 R3)"
    ]


def _request_arm_problems(record: str) -> list[str]:
    if "authorization: AuthorizationFacet" in body_of_variant(record, "Request"):
        return []
    return [f"{RECORD}: the Request record does not state an authorization outcome (R3)"]


def _response_arm_problems(record: str) -> list[str]:
    if "AuthorizationFacet" not in body_of_variant(record, "Response"):
        return []
    return [
        f"{RECORD}: a Response record carries an authorization coordinate — authorization "
        f"is request-side (ADR-MCPRE-066 R5)"
    ]


def record_problems(record: str) -> list[str]:
    """7/8. the record kind decides what each authority may say (R3, R5)."""
    return (
        _optional_facet_problems(record)
        + _request_arm_problems(record)
        + _response_arm_problems(record)
    )


def facet_projection_problems(serving: str) -> list[str]:
    """9. the facet is projected from an owner, never assembled at the audit site."""
    return [
        f"the serving path builds `{bad}` itself instead of asking the owner for its "
        f"projection (ADR-MCPRE-066 invariant 5 / R-COMPOSE)"
        for bad in ("AuthorizationFacet::Authorized(", "AuthorizationFacet::Refused(",
                    "AuthorizationAttribution {")
        if bad in serving
    ]


def core_audit_problems(core_audit: str) -> list[str]:
    """10. no audit rejection constructor takes a string."""
    if not re.search(r"fn\s+\w*rejected\w*\s*\(\s*\w+\s*:\s*&'static str", core_audit):
        return []
    return [
        f"{CORE_AUDIT}: an audit rejection constructor takes a `&'static str` — that is "
        f"the join where two authorities' tokens become one (ADR-MCPRE-066 invariant 8/9)"
    ]


def audit_token_problems(serving: str) -> list[str]:
    """11. the serving path never renders a token into an audit event."""
    return [
        "the serving path renders a token into an `AuditEvent` constructor instead "
        "of passing a typed Core verdict (ADR-MCPRE-066 invariant 9)"
        for m in re.finditer(r"AuditEvent::\w+\(", serving)
        if ".wire_code()" in serving[m.end() : m.end() + 160].split(";")[0]
    ]
