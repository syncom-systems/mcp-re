# SPDX-License-Identifier: Apache-2.0
"""The failures the MCP-RE transport adapter names (see :mod:`mcp_re_sdk.transport`).

Each is an :class:`~mcp_re_sdk.custody.McpReSdkError`: a condition the SDK itself
originated, never a frozen ``mcp-re.*`` token the peer sent.
"""
from __future__ import annotations

from .custody import McpReSdkError

__all__ = [
    "ClientResponseUnsupported",
    "ConnectionClosed",
    "ContinuationNotAnswered",
    "NotificationNotAcknowledged",
    "VerifiedReplyNotAResponse",
]


class ClientResponseUnsupported(McpReSdkError):
    """The session tried to send a client->server RESPONSE, which has no MCP-RE carrier.

    A server-initiated request (sampling, elicitation over the same session) would be
    answered by a JSON-RPC response travelling client->server. MCP-RE profiles two client
    message shapes — a request that earns a signed reply, and a notification that earns a
    signed bodyless 202 — and a response is neither.

    Failing closed here is the narrow choice on purpose. The alternative the notification
    path makes available is worse: a response has no `method`, so carrying it as a
    notification would mean signing a fabricated message and reporting the acknowledgement
    of THAT as if the response had been delivered.
    """


class NotificationNotAcknowledged(McpReSdkError):
    """A notification was transmitted and its acknowledgement did not verify.

    The message left this process. What could not be established is that the enforcement
    boundary authenticated and accepted it: the 202 was absent, unsigned, signed by an
    untrusted key, or bound to a different transmission.

    A notification has no reply for a JSON-RPC error to ride back on and no request id to
    correlate one to, so this is reported to :attr:`McpReConfig.on_undeliverable` rather
    than delivered to the session. The notification is NOT treated as delivered — nothing
    acknowledges it, which is the honest outcome for a message whose acknowledgement did
    not verify — and unrelated exchanges are untouched: the peer decides when a 202 fails
    to verify, so ending the session on one would hand it a session kill.

    ``wire_code`` carries the frozen ``mcp-re.*`` reason when the failure has one.
    """

    def __init__(self, method: str, wire_code: str) -> None:
        super().__init__(
            f"'{method}' was sent but its acknowledgement did not verify ({wire_code}); "
            f"the transport is failing closed rather than treating it as delivered"
        )
        self.method = method
        self.wire_code = wire_code


class ConnectionClosed(McpReSdkError):
    """The transport is not open for work: not started, or closing/closed.

    Also what queued and in-flight local requests fail with when ``close`` aborts them.

    **This says nothing about the server.** Cancelling a local ``poster`` call does not
    mean the request never arrived or that already-dispatched remote work has stopped —
    only that this client will not process an answer to it.
    """


class ContinuationNotAnswered(McpReSdkError):
    """A verified elicitation could not be answered, so the call did not complete.

    An ADR-MCPS-047 `InputRequiredResult` is a PAUSE, not an outcome. When no answer leg
    can be driven — no ``answer_input_required`` handler, a handler that declined, or a
    server that elicited past ``max_continuation_rounds`` — the exchange ends here.

    It ends as an ERROR, never as a result. Handing the pause up as the reply to
    ``call_tool`` would present a call that is still waiting for input as one that
    finished, which is the misrepresentation the continuation profile's protected
    non-terminal classification exists to make detectable (§5.2, §9.3).
    """


class VerifiedReplyNotAResponse(McpReSdkError):
    """A verified reply body is not a JSON-RPC RESPONSE, so it is not an answer at all.

    A signature proves the server said these bytes. It does not prove the bytes are a
    reply to anything. The one shape ``ClientSession`` is awaiting is a response object
    carrying exactly one of ``result`` / ``error``; every other shape is refused here
    rather than handed to the parser.

    The shape that makes this urgent rather than tidy: a body carrying a legal ``result``
    AND a top-level ``method`` re-parses as a ``JSONRPCRequest``, and the session
    dispatches it as a SERVER-INITIATED request — ``sampling/createMessage``,
    ``elicitation/create``, ``roots/list`` — running the application's registered
    handlers on attacker-chosen params over a channel MCP-RE profiles no carrier for.
    The tool call that was actually made then hangs forever, because its id was consumed
    as an inbound request id and nothing ever answers it.
    """
