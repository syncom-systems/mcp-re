# SPDX-License-Identifier: Apache-2.0
"""What the transport hands the MCP session: a verified reply as plain MCP, or an error.

Both shapes are built here from VERIFIED facts only. A reply is rebuilt from the one
member the server sent and the session's own id, and a refusal is a JSON-RPC error
correlated to the request, so the awaiting call raises instead of hanging.
"""
from __future__ import annotations

import json
from typing import Any

from mcp.shared.message import SessionMessage
from mcp.types import ErrorData, JSONRPCError, jsonrpc_message_adapter

from .transport_errors import VerifiedReplyNotAResponse


#: JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
#: always the frozen `mcp-re.*` token in `.message`.
#:
#: This envelope is synthesized locally by the transport, never received from the peer, so
#: MCP 2026-07-28 requires that it cannot be mistaken for a peer error: it sits outside
#: JSON-RPC's reserved band, and it differs from the proxy's own rejection code (-31000) so
#: a caller can tell "my transport refused this" from "the peer rejected this".
_MCP_RE_ERROR_CODE = -31001


# A verified rejection receipt that carried no (or an empty) wire code. The receipt is a
# genuine refusal whose signature verified, so no `mcp-re.*` token may stand in for the one
# the peer did not send; the condition is the SDK's own and carries its prefix.
_NO_PEER_WIRE_CODE = "mcp-re-sdk: verified rejection carried no wire code"


def _refuse_non_response(doc: Any) -> None:
    """Raise unless the verified reply is a JSON object with no top-level `method`."""
    if not isinstance(doc, dict):
        raise VerifiedReplyNotAResponse(
            f"a verified reply must be a JSON-RPC response object, got {type(doc).__name__}"
        )
    if "method" in doc:
        # A JSON-RPC response has no `method`. Its presence is what makes the union
        # adapter pick the REQUEST arm, so this is not a stray field — it is the whole
        # confusion. Refused rather than dropped: rebuilding would silently accept a
        # reply the peer deliberately shaped as something else.
        raise VerifiedReplyNotAResponse(
            "a verified reply carries a top-level `method`; a JSON-RPC response has none"
        )


def _response_member(doc: Any) -> str:
    """The one of ``result`` / ``error`` a verified reply carries, or raise."""
    _refuse_non_response(doc)
    members = [member for member in ("result", "error") if member in doc]
    if len(members) == 2:
        raise VerifiedReplyNotAResponse(
            "a verified reply carries both a result and an error"
        )
    if not members:
        raise VerifiedReplyNotAResponse(
            "a verified reply carries neither a result nor an error"
        )
    return members[0]


def _plain_response_object(doc: Any) -> dict:
    """The verified reply as a JSON-RPC RESPONSE, or raise.

    REBUILT rather than edited in place, which is the whole point: an envelope
    reconstructed from ``id`` plus the one member the server sent cannot smuggle a
    ``method`` (or anything else) past the parser, whatever the body carried. Mirrors the
    Rust ambassador's ``plain_response_from_verified``.
    """
    member = _response_member(doc)
    return {"jsonrpc": "2.0", "id": doc.get("id"), member: doc[member]}


def _plain_mcp_reply(body: bytes, request_id) -> bytes:
    """The verified reply as plain MCP: evidence block removed, id the session's own.

    Read only AFTER verification: the content-digest covered these bytes.

    MCP-RE's own evidence is not part of the MCP result, and the rebuild below drops it
    with every other top-level member the server sent. The id is
    restored because an ADR-MCPS-047 answer leg is an independent request with its own
    id (SEP-2322 §retry), while the session issued exactly one call and is awaiting the
    id it chose. Relabelling is the adapter's job at that seam — every hop was verified
    here, so the terminal result it hands up is a complete record (§9.3), not a spliced
    one.

    The envelope is REBUILT from the one member the server sent, not edited in place.
    Editing left every other top-level key in the document, and a body carrying both a
    legal ``result`` and a ``method`` then re-parsed as a server->client REQUEST — see
    :class:`VerifiedReplyNotAResponse`. Rebuilding removes the whole class: nothing the
    reply carries beyond ``result`` / ``error`` survives to reach the parser.
    """
    response = _plain_response_object(json.loads(body))
    response["id"] = request_id
    return json.dumps(response).encode()


def _error_message(request_id, wire_code: str, data: Any = None) -> SessionMessage:
    """A JSON-RPC error correlated to the request, so the awaiting call raises.

    ``data`` carries structured facts about the verdict that are not part of the frozen
    token — the token itself stays exactly what the peer said.
    """
    return SessionMessage(
        JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=ErrorData(code=_MCP_RE_ERROR_CODE, message=wire_code, data=data),
        )
    )


def _rejection_data(verified) -> dict:
    """The structured facts a verified rejection receipt carried, for ``error.data``.

    ``requestBound`` is the core's verdict on whether the receipt is tied to THIS
    transmission (RSP-7). The rest is the ADR-MCPRE-058 §10 execution / retry contract
    the server derived from its exchange machine and signed into the body: without it a
    post-dispatch refusal is indistinguishable from an ordinary outage, and the caller's
    retry re-executes a tool call that already ran.

    Only members the receipt actually carried are emitted. An absent ``executionStatus``
    means the server stated nothing, and inventing ``not_executed`` for it would collapse
    "unknown whether it ran" into "it did not run" at the one place that decides. The
    TypeScript twin emits the same keys — this is behaviour, so byte fixtures do not
    cover it.
    """
    data: dict = {"requestBound": bool(verified.bound)}
    for key, value in (
        ("executionStatus", verified.execution_status),
        ("retrySafety", verified.retry_safety),
        ("continuationStatus", verified.continuation_status),
        ("retentionStatus", verified.retention_status),
    ):
        if value is not None:
            data[key] = value
    return data


def _rejection_message(request_id, verified) -> SessionMessage:
    """The correlated error a verified rejection receipt is delivered as.

    A verified rejection receipt is genuine evidence, but it is NOT an acceptance: it
    must reach the app as an error, never as a result.

    `bound` is the core's verdict on whether the receipt is tied to THIS transmission. A
    preflight-unbound receipt carries no binding to this request's nonce or evidence, so
    one such signed receipt answers any request from any client of that issuer for the
    credential's whole validity window. It is still an error and never a result, but the
    application must be able to tell "the boundary rejected MY request" from "a generic
    rejection arrived" (RSP-7), so the binding fact travels in `data` — beside the frozen
    token rather than inside it, because the token is what the peer said.
    """
    return _error_message(
        request_id,
        verified.wire_code or _NO_PEER_WIRE_CODE,
        data=_rejection_data(verified),
    )


def _terminal_message(body: bytes, request_id) -> SessionMessage:
    """The verified terminal reply as the session's message, or the refusal to deliver it.

    The union adapter accepts a JSONRPCRequest, so the shape check has to happen BEFORE
    it: a verified body carrying a `method` would otherwise be delivered to
    `ClientSession` as a server-initiated request. The rebuild inside
    `_plain_mcp_reply` is what makes that impossible; this turns the refusal into the
    correlated error the session is awaiting.
    """
    try:
        plain = _plain_mcp_reply(body, request_id)
    except VerifiedReplyNotAResponse as e:
        return _error_message(
            request_id,
            "mcp-re.malformed_envelope",
            data={"detail": str(e)},
        )
    return SessionMessage(jsonrpc_message_adapter.validate_json(plain))
