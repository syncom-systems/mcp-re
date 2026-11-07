# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for how the transport adapter delivers a failed exchange: wire,
local and deadline failures reach the session as correlated JSON-RPC errors, the frozen
wire code is never invented, and an undeliverable message reaches the configured sink.
"""
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCNotification  # noqa: E402
from mcp_re_sdk import (  # noqa: E402
    CorrelationStore,
    HttpReply,
    McpReError,
    NotificationNotAcknowledged,
    SignerUnavailable,
)
from mcp_re_sdk.mtls import MtlsTransportError  # noqa: E402
from mcp_re_sdk.transport import _Dispatcher, _pump  # noqa: E402
from transport_fixtures import (  # noqa: E402
    capturing_notification_failures,
    drain,
    make_config,
    make_request,
    send_one,
    throwing_poster,
)


# --- failure delivery ------------------------------------------------------------


@pytest.mark.anyio
async def test_a_wire_failure_is_delivered_as_a_correlated_json_rpc_error():
    out = await send_one(
        make_config(),
        throwing_poster(McpReError("mcp-re.replay_detected", "seen before")),
        make_request(),
    )
    error = out[0].message
    assert error.id == 7
    assert error.error.code == -31001
    assert error.error.message == "mcp-re.replay_detected"


def _wire_refusal(token: str) -> ValueError:
    """A refusal shaped as the binding raises one."""
    from mcp_re_sdk import _core

    e = _core.WireRefusal(token)
    e.wire_code = token
    return e


@pytest.mark.anyio
async def test_a_local_signer_failure_is_delivered_without_claiming_a_wire_code():
    # The device broke on this side of the boundary; nothing was transmitted, so no peer
    # rejected anything. Reporting `mcp-re.invalid_signature` here would be a lie.
    out = await send_one(make_config(), throwing_poster(SignerUnavailable("kms timeout")), make_request())
    message = out[0].message.error.message
    assert message.startswith("mcp-re-sdk:")
    assert not message.startswith("mcp-re.")


@pytest.mark.anyio
async def test_the_cores_own_fail_closed_error_is_delivered_rather_than_hanging():
    out = await send_one(
        make_config(), throwing_poster(_wire_refusal("mcp-re.response_sig_invalid")), make_request()
    )
    assert out[0].message.error.message == "mcp-re.response_sig_invalid"




@pytest.mark.anyio
async def test_an_unexpected_exception_is_delivered_without_claiming_a_wire_code():
    # A defect is not a protocol outcome, so it must not be laundered into a `mcp-re.*`
    # token — but it must still be DELIVERED. It arrives named, correlated to the request
    # that hit it, under the prefix that means "local condition".
    out = await send_one(make_config(), throwing_poster(RuntimeError("boom")), make_request())

    message = out[0].message.error.message
    assert out[0].message.id == 7
    assert message.startswith("mcp-re-sdk: RuntimeError:")
    assert "boom" in message
    assert not message.startswith("mcp-re."), "a local defect must not claim a wire code"


@pytest.mark.anyio
async def test_one_exchanges_network_error_does_not_take_down_the_session():
    """The property that matters: a per-request failure stays per-request.

    Exchanges share one task group, so an exception escaping one would cancel every other
    in-flight exchange. A reset connection is ordinary and remotely triggerable — a peer
    that can cause one could otherwise end the session, and seven unrelated requests with
    it. Mirrors `transport.test.ts` — a poster rejection rejects only its own `send()`.
    """
    ids = []

    async def poster(method, target_uri, headers, body) -> HttpReply:
        body_doc = json.loads(body)
        ids.append(body_doc["id"])
        if body_doc["id"] == 1:
            raise ConnectionResetError("connection reset by peer")
        raise McpReError("mcp-re.replay_detected")

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    for rid in (1, 2, 3):
        await write_stream.send(SessionMessage(make_request(id=rid)))
    await write_stream.aclose()
    await _pump(_Dispatcher(make_config(), poster, read_writer), write_reader)

    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break

    assert sorted(ids) == [1, 2, 3], "the reset must not cancel the other exchanges"
    delivered = {m.message.id: m.message.error.message for m in out}
    assert delivered[1].startswith("mcp-re-sdk: ConnectionResetError:")
    assert delivered[2] == "mcp-re.replay_detected"
    assert delivered[3] == "mcp-re.replay_detected"


@pytest.mark.anyio
async def test_a_transport_deadline_does_not_synthesize_what_the_peer_never_said():
    """The aggregate response deadline reaches the application as a LOCAL failure.

    The composition this control exists for is `transport deadline → local transport
    failure → application-facing correlated outcome`, and it is the one a low-level
    `_read_bounded` test cannot reach. A future implementation could bound the read
    correctly and still lie about the remote side: report a `mcp-re.*` token nobody sent,
    or fill in `executionStatus: not_executed` / `retrySafety: retry_safe` for an exchange
    whose fate it does not know. Either would turn a timeout — the one condition under
    which the SDK knows LEAST about whether the call ran — into a licence to retry a tool
    call that already executed.

    So what is asserted is not only that the deadline fails the exchange, but everything
    the SDK must NOT say about it, and that the failure stays confined to its own
    correlated exchange.
    """
    store = CorrelationStore()

    async def poster(method, target_uri, headers, body) -> HttpReply:
        if json.loads(body)["id"] == 1:
            # Exactly what `mtls._read_bounded` raises when the aggregate bound expires.
            raise MtlsTransportError(
                "the aggregate response read exceeded 0.5s (slow-loris trickle)"
            )
        raise McpReError("mcp-re.replay_detected")

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    for rid in (1, 2):
        await write_stream.send(SessionMessage(make_request(id=rid)))
    await write_stream.aclose()
    await _pump(_Dispatcher(make_config(), poster, read_writer, store), write_reader)

    delivered = {m.message.id: m.message.error for m in drain(read_stream)}
    timed_out = delivered[1]

    # 1. The affected exchange fails, correlated to its own id. A dropped outcome would
    #    leave `ClientSession` awaiting a reply that never comes.
    assert timed_out is not None
    # 2. No peer verdict is claimed. The peer said nothing; a `mcp-re.*` token here would
    #    be the SDK speaking in the peer's voice.
    assert timed_out.message.startswith("mcp-re-sdk:")
    assert not timed_out.message.startswith("mcp-re.")
    # Delivered as the transport's own words under the local prefix — a `McpReSdkError`
    # is reported by message, so what arrives is the bound that fired, not a peer verdict.
    assert "aggregate response read" in timed_out.message
    # 3/4. No execution or retry fact is invented. These members exist only when a VERIFIED
    #      receipt carried them; a local timeout carries nothing, so the honest answer is
    #      their absence, not a value.
    rendered = json.dumps(timed_out.model_dump(mode="json"))
    for forbidden in ("not_executed", "notExecuted", "executionStatus", "retrySafety", "retry_safe"):
        assert forbidden not in rendered, f"a local timeout must not state {forbidden!r}"
    # 5. Unrelated exchanges are undisturbed, and nothing is left outstanding: a deadline
    #    that leaked its correlation entry would be a remotely triggerable growth lever.
    assert delivered[2].message == "mcp-re.replay_detected"
    assert len(store) == 0, "the timed-out exchange left its correlation entry outstanding"


# --- the frozen wire code --------------------------------------------------------
#
# The PyO3 binding raises a core refusal as `WireRefusal`, with the frozen token in
# `.wire_code`. What REQ-14/POL-6 make authoritative — and what a caller branches on
# without parsing prose — is that TOKEN, so it is read from the typed field.


@pytest.mark.anyio
async def test_a_core_refusal_is_delivered_as_its_wire_code():
    out = await send_one(
        make_config(),
        throwing_poster(_wire_refusal("mcp-re.response_sig_invalid")),
        make_request(),
    )
    assert out[0].message.error.message == "mcp-re.response_sig_invalid"


@pytest.mark.anyio
async def test_a_value_error_that_merely_says_a_token_is_a_local_condition():
    # The wire code is read from the binding's typed field, never parsed out of prose: a
    # `ValueError` from the caller's `poster` whose text happens to be a token is still
    # the caller's own condition.
    out = await send_one(
        make_config(), throwing_poster(ValueError("mcp-re.response_sig_invalid")), make_request()
    )
    assert out[0].message.error.message.startswith("mcp-re-sdk: ValueError: ")


@pytest.mark.anyio
async def test_a_value_error_that_is_not_a_token_is_labelled_a_local_condition():
    # A `ValueError` from the caller's `poster` doing real I/O must not occupy the field
    # that otherwise only ever holds something the peer said.
    out = await send_one(make_config(), throwing_poster(ValueError("socket hang up")), make_request())
    message = out[0].message.error.message
    assert message == "mcp-re-sdk: ValueError: socket hang up"


@pytest.mark.anyio
async def test_a_notifications_wire_code_is_the_bare_token_too():
    """`wire_code` is documented as the frozen token, so the notification path strips the
    binding's prefix exactly as the request path does. The TypeScript twin pins the same
    assertion."""
    import re

    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    seen = []
    with capturing_notification_failures(seen):
        await send_one(
            make_config(),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert re.fullmatch(r"mcp-re\.[a-z0-9_]+", seen[0][1].wire_code), seen[0][1].wire_code


# --- the undeliverable-message sink ----------------------------------------------


@pytest.mark.anyio
async def test_the_config_hook_takes_precedence_over_the_process_global_sink():
    """Two transports in one process must not swallow each other's failures.

    A module-level sink is shared by every transport in the process, so one embedder's
    assignment silently ate another's. The per-config hook is what an application
    installs to learn that a message it emitted was NOT delivered.
    """
    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    mine = []
    global_sink = []
    with capturing_notification_failures(global_sink):
        await send_one(
            make_config(on_undeliverable=lambda d, e: mine.append((d, e))),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert [d for d, _ in mine] == ["notifications/initialized"]
    assert [type(e) for _, e in mine] == [NotificationNotAcknowledged]
    assert global_sink == [], "the config hook must not also reach the process global"
