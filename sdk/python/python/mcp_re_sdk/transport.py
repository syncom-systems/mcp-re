# SPDX-License-Identifier: Apache-2.0
"""The MCP-RE transport adapter (ADR-MCPS-044 §wrap-or-fork rule).

``mcp.ClientSession`` speaks plain MCP; this adapter signs the outgoing bytes and
verifies the incoming bytes underneath it, so application code never calls
``sign_request`` / ``verify_response`` itself.

Why a transport and not a wrapper: the MCP Python SDK serializes JSON-RPC *inside* each
transport — the anyio stream between ``ClientSession`` and the transport carries parsed
pydantic objects, not bytes. The transport is therefore the only seam with exact-byte
control, which is what a byte-exact signature requires.

    application code
      -> mcp.ClientSession            plain MCP; unaware of MCP-RE
      -> mcp_re_http_transport        signs outbound bytes / verifies inbound bytes
      -> mcp_re_sdk._core (PyO3)      the audited mcp-re-client-core, in Rust
      -> mcp-re-proxy (HTTP profile)  one signed mTLS POST per request

**Every failure is delivered, correlated to the request id, as a JSON-RPC error.** A
transport that dropped a failed exchange would leave ``ClientSession`` awaiting a reply
that never comes; a hang is a worse failure mode than a raise, and an unverifiable
response must never reach the application as a result.

**One-way notifications are carried, not dropped.** A notification is its own signed
POST, and the acknowledgement it earns — a signed bodyless 202 bound to that exact
transmission — is verified before the adapter treats it as delivered. See
:class:`NotificationNotAcknowledged` for what happens when it is not.

**A multi-round-trip call is driven to a terminal result.** An ADR-MCPS-047 elicitation
pauses a call rather than finishing it, so the adapter signs the answer leg over the
verified handles of the leg before it and continues until the server returns a terminal
result — that result, and only that, is what the session's await resolves to. Install
:attr:`McpReConfig.answer_input_required` to supply the answers; without it an
elicitation fails closed (:class:`ContinuationNotAnswered`) rather than reaching the
application as if the call had completed.

MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
a ``poster`` so this layer stays transport-agnostic and testable; :func:`connect_mtls_http
<mcp_re_sdk.mtls.connect_mtls_http>` (the mTLS construction helper) builds on top of it.
"""
from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from typing import Any, Mapping, Optional

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest

from . import _core
from .correlation import ContinuationHandles, CorrelationStore
from .custody import McpReError, McpReSdkError
from .transport_binding import _authz_binding_digest, _bindings_json
from .transport_config import MAX_CLOCK_SKEW_BOUND as MAX_CLOCK_SKEW_BOUND
from .transport_config import HttpReply, McpReConfig
from .transport_config import Poster as Poster
from .transport_continuation import InputAnswer as InputAnswer
from .transport_continuation import (
    InputRequired,
    _answer_leg_id,
    _answer_leg_params,
    _elicited_answers,
    _verified_result,
)
from .transport_envelope import (
    _error_message,
    _rejection_message,
    _terminal_message,
)
from .transport_errors import (
    ClientResponseUnsupported,
    ConnectionClosed,
    ContinuationNotAnswered,
    NotificationNotAcknowledged,
    VerifiedReplyNotAResponse,
)
from .transport_freshness import MIN_NONCE_CHARS as MIN_NONCE_CHARS
from .transport_freshness import _checked_nonce

__all__ = [
    "ClientResponseUnsupported",
    "ConnectionClosed",
    "ContinuationNotAnswered",
    "HttpReply",
    "InputRequired",
    "McpReConfig",
    "NotificationNotAcknowledged",
    "VerifiedReplyNotAResponse",
    "mcp_re_http_transport",
    "send_notification_verified",
]

#: Past every possible deadline: close reaps ALL outstanding correlation entries, not the
#: merely-expired ones.
_FAR_FUTURE = 2**63 - 1


def _verifier_inputs(config: McpReConfig, reply: HttpReply, signed) -> tuple:
    """The positional arguments the core's verifiers take for one transmission.

    The verdict is about the transmission, so the request side is the value
    ``sign_request`` / ``sign_notification`` produced — the very bytes that were posted —
    and the trust side is the configured delegated-verification anchor. One definition
    serves the reply verifier and the acknowledgement verifier, which take the same list.
    """
    return (
        reply.status,
        list(reply.headers),
        reply.body,
        signed.method,
        signed.target_uri,
        list(signed.headers),
        signed.body(),
        config.issuer_key_id,
        config.issuer_pubkey_b64url,
        config.issuer_role,
        config.issuer_trust_domain,
        config.issuer_subject,
        list(config.verifier_audiences),
        config.expected_audience_hash,
        list(config.accepted_epochs),
        config.max_clock_skew,
        list(config.revoked_identifiers),
        config.clock(),
    )


class _Call:
    """One logical call being driven to a terminal result: its legs and their state.

    An ADR-MCPS-047 elicitation does not end the call — it pauses it. So this drives the
    whole chain: every leg is signed, posted and verified here, and an answer leg binds
    to the verified handles of the leg before it. What it yields is the TERMINAL result
    the session asked for, or a JSON-RPC error carrying the frozen wire code from
    whichever hop failed.

    Because every hop verified, handing up the terminal result is honest under §9.3 of
    the continuation profile: a chain with an unverifiable middle hop never gets here.
    """

    def __init__(
        self,
        config: McpReConfig,
        poster: Poster,
        request: JSONRPCRequest,
        correlation: CorrelationStore,
    ) -> None:
        self.config = config
        self.poster = poster
        self.request = request
        self.correlation = correlation
        self.method = request.method
        self.params: Mapping[str, Any] = request.params if request.params is not None else {}
        self.leg_id = request.id
        self.cont: Optional[ContinuationHandles] = None
        self.round_index = 0
        # Correlation entries this call still holds. An open leg stays outstanding while
        # its answer leg runs — ADR-MCPS-047 associates without consuming — so there can
        # be more than one, and every entry left here when the call ends is retired.
        self.outstanding: set = set()

    async def run(self) -> SessionMessage:
        try:
            while True:
                message = await self._leg()
                if message is not None:
                    return message
        finally:
            # Whatever is still outstanding can never be bound now: a failed leg gets no
            # answer, and an open leg's answer leg has either terminated the call or
            # failed with it. Everything that lands here is remotely triggerable — a
            # reset connection, an unverifiable reply, an elicitation nobody answers — so
            # leaving entries outstanding would let a peer grow the store one call at a
            # time, for the life of the session. Retiring them is not a security
            # decision: a response arriving for one afterwards is refused either way.
            for correlation_id in self.outstanding:
                self.correlation.abandon(correlation_id)

    async def _leg(self) -> Optional[SessionMessage]:
        """Run one leg; the call's final message, or ``None`` when an answer leg follows."""
        config = self.config
        signed, correlation_id = self._sign_and_record()

        reply = await self.poster(signed.method, signed.target_uri, signed.headers, signed.body())

        verified = _core.verify_response(*_verifier_inputs(config, reply, signed))

        if verified.outcome != "success":
            self._retire(correlation_id)
            return _rejection_message(self.request.id, verified)

        if verified.request_state is None:
            self._retire(correlation_id)
            return _terminal_message(reply.body, self.request.id)

        await self._pause(correlation_id, verified, reply.body)
        return None

    def _sign_and_record(self):
        """Sign this leg and record it as outstanding; the signed request and its handle."""
        config = self.config
        created = config.clock()
        expires = created + config.request_ttl
        bindings_json = _bindings_json(config, self.method)

        signed = config.signer.sign_request(
            id_json=json.dumps(self.leg_id),
            method=self.method,
            params_json=json.dumps(self.params),
            target_uri=config.target_uri,
            audience_id=config.audience_id,
            route=config.route,
            dpop_token=config.dpop_token,
            nonce=_checked_nonce(config.nonce_factory),
            created=created,
            expires=expires,
            bindings_json=bindings_json,
            **(self.cont.as_sign_kwargs() if self.cont is not None else {}),
        )
        correlation_id = self.correlation.record(
            signed,
            request_id=str(self.leg_id),
            nonce="",  # the nonce rode into the signature; the handle is the digest
            audience_id=config.audience_id,
            expected_signer_id=config.issuer_key_id,
            created=created,
            expires=expires,
            route=config.route,
            authz_binding_digest=_authz_binding_digest(bindings_json),
        )
        self.outstanding.add(correlation_id)
        return signed, correlation_id

    def _retire(self, correlation_id) -> None:
        """Consume a leg's entry: it has its answer, so it is no longer outstanding."""
        self.correlation.take(correlation_id, now=self.config.clock())
        self.outstanding.discard(correlation_id)

    async def _pause(self, correlation_id, verified, reply_body: bytes) -> None:
        """Handle a verified pause: answer the elicitation and prepare the next leg.

        Associates without consuming — the open leg is answered by its answer leg, not by
        this response — and hands up the handles the answer leg signs over.
        """
        config = self.config
        handles = self.correlation.record_input_required(
            correlation_id,
            response_digest_alg=verified.resp_evidence_digest_alg,
            response_digest_value=verified.resp_evidence_digest_value,
            request_state=verified.request_state,
            now=config.clock(),
        )
        if config.on_input_required is not None:
            config.on_input_required(handles)

        self.round_index += 1
        elicitation = InputRequired(
            handles=handles,
            method=self.method,
            params=self.params,
            result=_verified_result(reply_body),
            round=self.round_index,
        )
        responses = await _elicited_answers(config, elicitation)

        # The next leg: the same call, carrying the answers and echoing the opaque state
        # back, bound to the handles of the exchange that asked for them.
        self.params = _answer_leg_params(elicitation, responses)
        self.leg_id = _answer_leg_id(self.request.id, self.round_index)
        self.cont = handles


async def _notify(config: McpReConfig, poster: Poster, method: str, params) -> None:
    """Sign one notification, POST it, and verify the acknowledgement it earns.

    A notification is signed by the ordinary request rules — same evidence block, same
    covered components, same freshness triple. What it gets back is a signed bodyless
    202 whose `;req` components plus `mcp-re-request-evidence` bind it to THIS
    transmission (owner ruling C019b), so a 202 captured from an earlier send of the
    same notification does not verify here.

    Raises :class:`NotificationNotAcknowledged` on any failure. There is deliberately no
    "sent it anyway" path: an unverified acknowledgement establishes nothing, and
    treating it as delivery is the take-it-on-faith posture the profile removes.
    """
    created = config.clock()
    expires = created + config.request_ttl
    bindings_json = _bindings_json(config, method)

    signed = config.signer.sign_notification(
        method=method,
        params_json=json.dumps(params if params is not None else {}),
        target_uri=config.target_uri,
        audience_id=config.audience_id,
        route=config.route,
        dpop_token=config.dpop_token,
        nonce=_checked_nonce(config.nonce_factory),
        created=created,
        expires=expires,
        bindings_json=bindings_json,
    )

    reply = await poster(signed.method, signed.target_uri, signed.headers, signed.body())
    accepted = _verified_acknowledgement(config, reply, signed, method)

    if config.on_notification_acknowledged is not None:
        config.on_notification_acknowledged(method, accepted.server_keyid)


def _verified_acknowledgement(config: McpReConfig, reply: HttpReply, signed, method: str):
    """The verified acknowledgement of a notification, or :class:`NotificationNotAcknowledged`."""
    try:
        return _core.verify_accepted_202(*_verifier_inputs(config, reply, signed))
    except McpReError as e:
        raise NotificationNotAcknowledged(method, e.wire_code) from e
    except _core.WireRefusal as e:
        # The core's fail-closed refusal carries its frozen token in `.wire_code`.
        raise NotificationNotAcknowledged(method, e.wire_code) from e
    except ValueError as e:
        # Any other ValueError is a local condition, and says so rather than travelling
        # as a wire code.
        raise NotificationNotAcknowledged(
            method, f"mcp-re-sdk: {type(e).__name__}: {e}"
        ) from e


async def send_notification_verified(
    config: McpReConfig, poster: Poster, method: str, params: Any = None
) -> None:
    """Send ONE notification and return only once its signed 202 has verified.

    SD-03 says neither SDK may treat a notification as delivered until its 202 verifies.
    The TypeScript twin gives its caller that guarantee directly: ``send()`` awaits the
    whole obligation and throws :class:`NotificationNotAcknowledged`. This is the Python
    surface with the same contract, and it is a separate call because
    ``ClientSession.send_notification()`` cannot have it: that method hands the message
    to an anyio memory stream and returns, so the pump on the other side has no caller
    left to raise to. Reaching back through the pump would mean raising inside the task
    group that runs every concurrent exchange — the remotely-triggerable session kill
    round 5 removed, where one unverifiable 202 for a routine notification cancels every
    unrelated in-flight tool call.

    So an application that must know its ``notifications/cancelled`` reached the
    enforcement boundary calls this and handles the exception. One that routes
    notifications through ``ClientSession`` gets the contained behaviour instead: the
    message is still never treated as delivered, and the failure is reported through
    :attr:`McpReConfig.on_undeliverable` (see :func:`_one_notification`).

    :raises NotificationNotAcknowledged: signing, POSTing, or verifying the 202 failed.
        Nothing acknowledged the message, which is exactly what the exception says.
    """
    await _notify(config, poster, method, params)


def _delivered_failure(request_id, error: Exception) -> SessionMessage:
    """The JSON-RPC error a failed exchange is delivered as.

    Every failure becomes a message. The session is awaiting this id, so returning
    without sending would hang it forever.
    """
    if isinstance(error, McpReError):
        return _error_message(request_id, error.wire_code)
    if isinstance(error, McpReSdkError):
        # A local failure (e.g. the signing device). No wire code describes it.
        return _error_message(request_id, f"mcp-re-sdk: {error}")
    if isinstance(error, _core.WireRefusal):
        # The core's own fail-closed refusal: deliver its frozen token rather than
        # letting the caller hang, because that is what the taxonomy pins and what a
        # caller branches on.
        return _error_message(request_id, error.wire_code)
    # Anything else — a `ValueError` from somewhere else, and in practice what is left is
    # dominated by the caller's `poster` doing real I/O: a reset connection, a TLS error,
    # a timeout. Exchanges run concurrently in one task group, so letting these escape
    # would cancel every OTHER in-flight exchange and tear down the session; one flaky
    # connection would take out seven unrelated requests, and a peer that can cause a
    # reset could end the session at will.
    #
    # It is delivered under the `mcp-re-sdk:` prefix and tagged with its type, never as a
    # bare `mcp-re.*` token, so it can never be read as something the peer said. A
    # genuine defect stays fully visible — it arrives named, as
    # `mcp-re-sdk: TypeError: ...`, correlated to the request that hit it — rather than
    # as an ExceptionGroup with the session gone.
    return _error_message(request_id, f"mcp-re-sdk: {type(error).__name__}: {error}")


def _report_undeliverable(
    config: McpReConfig, descriptor: str, error: BaseException
) -> None:
    """Surface an outbound message that was not delivered, without ending the session.

    Two events reach here, and neither has a request id a JSON-RPC error could be
    correlated to: a notification whose signed 202 did not verify, and a client->server
    response, which MCP-RE profiles no carrier for. This is therefore the only place
    either outcome is observable, and swallowing it entirely would be its own defect.

    :attr:`McpReConfig.on_undeliverable` first, so two transports in one process cannot
    swallow each other's failures; the module-level ``on_notification_failure`` is the
    process-wide fallback for a config that installs no hook of its own.
    """
    hook = config.on_undeliverable
    if hook is None:
        hook = on_notification_failure
    hook(descriptor, error)


def _default_undeliverable(descriptor: str, error: BaseException) -> None:
    print(
        f"mcp-re-sdk: {descriptor} was not delivered: {type(error).__name__}: {error}",
        file=sys.stderr,
    )


#: The process-wide fallback sink for an outbound message that was not delivered — a
#: notification whose acknowledgement did not verify, or a refused client->server
#: response. Replaceable by an embedder that wants the event routed somewhere other than
#: stderr; :attr:`McpReConfig.on_undeliverable` overrides it per transport.
on_notification_failure = _default_undeliverable


class _Dispatcher:
    """The outbound side of one session: what runs each message the session sends.

    Exchanges run concurrently, up to ``max_concurrent_exchanges``: awaiting each one
    before reading the next request would make a single slow tool call block every other
    request on the session. Requests and notifications share the one bound because they
    cost the same resources — a connection and a signing operation.
    """

    def __init__(
        self,
        config: McpReConfig,
        poster: Poster,
        read_writer,
        correlation: Optional[CorrelationStore] = None,
    ) -> None:
        self.config = config
        self.poster = poster
        self.read_writer = read_writer
        self.correlation = correlation if correlation is not None else CorrelationStore()
        self.limiter = anyio.CapacityLimiter(config.max_concurrent_exchanges)

    def dispatch(self, tg, message: JSONRPCMessage) -> None:
        """Start the work one outbound session message calls for."""
        if isinstance(message, JSONRPCNotification):
            # A one-way notification: its own signed POST, answered by a signed bodyless
            # 202 rather than a JSON-RPC reply.
            tg.start_soon(self.send_notification, message.method, message.params)
            return
        if not isinstance(message, JSONRPCRequest):
            # A client->server RESPONSE or error. It has no `method`, so the notification
            # path above could only carry it by signing a fabricated message; refuse it
            # instead of inventing one.
            #
            # REPORTED, not raised. The pump is the parent task of the task group that
            # runs every concurrent exchange, so raising here cancels all of them and
            # ends the transport — and the trigger is peer-influenceable: a verified
            # reply body carrying a `method` parses as a server->client request,
            # `ClientSession` answers it with a response, and that answer arrives right
            # here. One reply body would end an entire session, including every
            # unrelated in-flight signed tool call. The TypeScript twin fails only the
            # one `send()`.
            _report_undeliverable(
                self.config,
                type(message).__name__,
                ClientResponseUnsupported(
                    f"{type(message).__name__} is a client->server response; "
                    f"MCP-RE profiles a signed request and a signed "
                    f"notification, and a response is neither"
                ),
            )
            return
        tg.start_soon(self.exchange, message)

    async def exchange(self, request: JSONRPCRequest) -> None:
        """Run one exchange to completion and deliver its outcome to the session.

        Every failure becomes a message (see :func:`_delivered_failure`). The session is
        awaiting this id, so returning without sending would hang it forever.

        ``BaseException`` is deliberately NOT caught: cancellation must propagate, or
        ``close()`` could not abort an in-flight exchange.
        """
        async with self.limiter:
            try:
                message = await _Call(
                    self.config, self.poster, request, self.correlation
                ).run()
            except Exception as e:
                message = _delivered_failure(request.id, e)
        await self.read_writer.send(message)

    async def send_notification(self, method: str, params) -> None:
        """Run one notification to completion under the concurrency bound.

        A notification has no request id and no caller awaiting a reply, so a failure
        cannot be DELIVERED as a JSON-RPC error the way :meth:`exchange` delivers one. It
        must still not take the session with it.

        Letting it propagate did exactly that: notifications are started with
        ``tg.start_soon`` in the SAME task group that runs every concurrent exchange, so
        one unverifiable signed 202 — for a routine ``notifications/initialized``, from a
        proxy whose delegated key is merely past ``exp`` or whose trust epoch is stale —
        cancelled every other in-flight tool call and tore the transport down. That is
        the remotely-triggerable session kill round 5 fixed on the request path, and the
        peer controls the trigger. The TypeScript twin fails only the one ``send()``.

        So the failure is contained and reported on the diagnostic channel instead. The
        notification is NOT treated as delivered — nothing acknowledges it, which is the
        honest outcome for a message whose acknowledgement did not verify — and unrelated
        exchanges continue.

        ``BaseException`` is deliberately not caught: cancellation must still propagate,
        or ``close()`` could not abort an in-flight notification.
        """
        async with self.limiter:
            try:
                await _notify(self.config, self.poster, method, params)
            except Exception as e:  # noqa: BLE001 - see the docstring
                _report_undeliverable(self.config, method, e)


async def _pump(dispatcher: _Dispatcher, write_reader) -> None:
    """Drive every outbound session message through the MCP-RE obligation."""
    async with write_reader, dispatcher.read_writer:
        # The task group closes INSIDE the streams: it waits for every in-flight exchange
        # before the streams are closed, so a slow exchange can still deliver its reply
        # rather than failing to send on a closed stream.
        async with anyio.create_task_group() as tg:
            async for outgoing in write_reader:
                dispatcher.dispatch(tg, outgoing.message)


@asynccontextmanager
async def mcp_re_http_transport(
    config: McpReConfig,
    poster: Poster,
    *,
    correlation: Optional[CorrelationStore] = None,
):
    """An MCP client transport that signs requests and verifies responses.

    Yields the ``(read_stream, write_stream)`` pair ``mcp.ClientSession`` expects::

        async with mcp_re_http_transport(config, poster) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("read_file", {"path": "/etc/hosts"})

    The signer is checked against the route's policy before anything is signed, so a
    custody violation fails the connection rather than a request.

    In-flight correlation state belongs to ONE transport, not to the config: the config
    is a value object a caller may reasonably reuse, and two transports sharing a store
    would let either one clear the other's outstanding requests on close. A store is
    created per invocation; pass ``correlation`` only to observe it (the TypeScript
    transport exposes the same state as ``pendingCorrelations``).
    """
    if correlation is None:
        correlation = CorrelationStore()
    if config.policy is not None:
        config.policy.check(config.signer)
    if config.authorization_policy is not None:
        config.authorization_policy.check(list(config.authorization))

    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)
    dispatcher = _Dispatcher(config, poster, read_writer, correlation)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_pump, dispatcher, write_reader)
        try:
            yield read_stream, write_stream
        finally:
            # Abortive close (#421), matching the upstream client's rejection of pending
            # requests: in-flight exchanges are cancelled rather than drained, and the
            # streams close, so a later send fails and no reply can be delivered to a
            # caller that has left the block.
            #
            # This makes NO claim that already-dispatched remote work has stopped: the
            # server may have received the request and acted on it. Only that this client
            # will not process an answer.
            tg.cancel_scope.cancel()
            # Abandoned entries would otherwise outlive the transport that owns them.
            correlation.expire_before(_FAR_FUTURE)
