# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for the transport adapter's lifecycle and notifications: the
obligations that hold regardless of what a counterparty says.

The live proof — a real ``mcp.ClientSession`` against the real proxy and a real FastMCP
backend — is in ``test_transport_e2e.py``; these cover the paths a happy round-trip never
reaches, with an injected ``poster`` and no network. Mirrors
``sdk/typescript/test/transport.test.ts``.

The theme throughout: **a failure must be DELIVERED, not dropped.** A transport that
swallowed a failed exchange would leave ``ClientSession`` awaiting a reply that never
comes, and a hang is a worse failure mode than a raise.
"""
import contextlib
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCNotification  # noqa: E402
from mcp_re_sdk import (  # noqa: E402
    AuthorizationBindingPolicy,
    ClientResponseUnsupported,
    HttpReply,
    mcp_re_http_transport,
    McpReError,
    NotificationNotAcknowledged,
    OpaqueBytesProvider,
    Signer,
    SignerPolicy,
    SigningDevice,
)
from mcp_re_sdk.transport import _Dispatcher, _pump  # noqa: E402
from transport_fixtures import (  # noqa: E402
    capturing_notification_failures,
    capturing_poster,
    CLIENT_SEED,
    make_config,
    make_request,
    send_one,
    TARGET,
    throwing_poster,
)


# --- lifecycle -------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_signer_is_checked_before_anything_is_signed():
    posted = []
    config = make_config(policy=SignerPolicy.hardened("did:example:host-a"))
    with pytest.raises(McpReError) as ei:
        async with mcp_re_http_transport(config, capturing_poster(posted)):
            pass
    assert ei.value.wire_code == "mcp-re.actor_binding_failed"
    # A custody violation must fail the CONNECTION; nothing may reach the wire.
    assert posted == []


@pytest.mark.anyio
async def test_the_authorization_policy_is_checked_at_open_too():
    config = make_config(
        authorization=[OpaqueBytesProvider("oauth-rar", b"doc")],
        authorization_policy=AuthorizationBindingPolicy.permitting(["human-approval"]),
    )
    with pytest.raises(McpReError) as ei:
        async with mcp_re_http_transport(config, throwing_poster(RuntimeError("unreachable"))):
            pass
    assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"


@pytest.mark.anyio
async def test_a_satisfied_policy_opens_the_transport():
    config = make_config(policy=SignerPolicy("did:example:host-a", profile="development"))
    async with mcp_re_http_transport(config, throwing_poster(RuntimeError())) as (read, write):
        assert read is not None and write is not None


# --- notifications ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_notification_is_transmitted_as_a_signed_post():
    """It goes on the wire, signed by the ordinary request rules.

    The adapter used to refuse or drop it: MCP-RE had no ratified one-way profile, so a
    `notifications/cancelled` silently became "keep going". The profile exists now (#418
    / C019b), so the message is carried and its acknowledgement is checked.
    """
    posted = []
    # The capturing poster never returns a 202, so the ack check fails closed; the
    # failure is contained rather than ending the session, and what this test reads is
    # the request that DID reach the wire.
    with capturing_notification_failures([]):
        await send_one(
            make_config(),
            capturing_poster(posted),
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )

    assert len(posted) == 1, "the notification must reach the wire"
    names = {k.lower() for k, _ in posted[0]["headers"]}
    assert {"signature", "signature-input", "content-digest"} <= names
    body = json.loads(posted[0]["body"])
    assert body["method"] == "notifications/initialized"
    # The serving path classifies a notification by an ABSENT id. `null` is a present id
    # and would be dispatched as a request, answered with a bodied reply nothing awaits.
    assert "id" not in body
    assert body["_meta"], "the request evidence block rides along, as on any request"


@pytest.mark.anyio
async def test_an_unsigned_acknowledgement_fails_the_transport_closed():
    """A 202 with no evidence establishes nothing, so it must not pass as delivery.

    Failing closed means the notification is NOT treated as delivered — and, since
    round 6, that it does not take the session with it. Notifications are started in
    the same task group as every concurrent exchange, so letting the failure escape
    cancelled unrelated in-flight tool calls and tore the transport down on a trigger
    the PEER controls: one unverifiable acknowledgement for a routine
    `notifications/initialized`, from a proxy whose delegated key is merely past `exp`.
    That is the remotely-triggerable session kill round 5 fixed on the request path.
    """
    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    seen = []
    with capturing_notification_failures(seen):
        out = await send_one(
            make_config(),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )

    assert out == [], "an unverifiable acknowledgement delivers nothing to the session"
    assert [type(e) for _, e in seen] == [NotificationNotAcknowledged]
    assert seen[0][0] == "notifications/initialized"
    assert "mcp-re." in seen[0][1].wire_code


@pytest.mark.anyio
async def test_a_non_202_answer_to_a_notification_fails_closed():
    """The named bodyless set is checked as a set: a bodied 200 is not an
    acknowledgement, however well-formed it looks."""
    async def bodied(method, target_uri, headers, body):
        return HttpReply(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=b'{"jsonrpc":"2.0","id":null,"result":{"ok":true}}',
        )

    seen = []
    with capturing_notification_failures(seen):
        out = await send_one(
            make_config(),
            bodied,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/cancelled"),
        )
    assert out == [], "a bodied 200 is not an acknowledgement"
    assert [type(e) for _, e in seen] == [NotificationNotAcknowledged]


@pytest.mark.anyio
async def test_a_client_side_response_is_refused_rather_than_carried_as_a_notification():
    """A response has no `method`. Signing one as a notification would fabricate a
    message and then report ITS acknowledgement as if the response had been delivered."""
    from mcp.types import JSONRPCResponse

    posted = []
    seen = []
    with capturing_notification_failures(seen):
        out = await send_one(
            make_config(),
            capturing_poster(posted),
            JSONRPCResponse(jsonrpc="2.0", id=1, result={}),
        )
    assert out == [], "a refused message delivers nothing to the session"
    assert [type(e) for _, e in seen] == [ClientResponseUnsupported]
    assert posted == [], "nothing fabricated may reach the wire"


@pytest.mark.anyio
async def test_a_refused_client_side_response_does_not_cancel_other_exchanges():
    """The refusal is correct; ending the session over it is not.

    ``_pump`` reads outbound messages in the parent task of the task group that runs
    every concurrent exchange, so raising there cancelled all of them. The trigger is
    peer-influenceable: a verified reply body carrying a ``method`` parses as a
    server->client ``JSONRPCRequest``, ``ClientSession`` answers it with a
    ``JSONRPCResponse``, and that answer lands on this branch — so one reply body ended
    an entire session, including every unrelated in-flight signed tool call. The
    TypeScript twin fails only the one ``send()``.
    """
    from mcp.types import JSONRPCResponse

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    # The refused message sits BETWEEN two ordinary requests, so a task-group unwind
    # would take out the one already in flight and never start the one behind it.
    await write_stream.send(SessionMessage(make_request(id=1)))
    await write_stream.send(SessionMessage(JSONRPCResponse(jsonrpc="2.0", id=99, result={})))
    await write_stream.send(SessionMessage(make_request(id=2)))
    await write_stream.aclose()

    seen = []
    with capturing_notification_failures(seen):
        await _pump(
            _Dispatcher(
                make_config(),
                throwing_poster(McpReError("mcp-re.replay_detected")),
                read_writer,
            ),
            write_reader,
        )

    delivered = []
    while True:
        try:
            delivered.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break
    assert sorted(m.message.id for m in delivered) == [1, 2], (
        "the refusal cancelled the exchanges around it"
    )
    assert [type(e) for _, e in seen] == [ClientResponseUnsupported]


@pytest.mark.anyio
async def test_a_sub_floor_nonce_override_is_refused_before_a_notification_is_signed():
    """The nonce floor governs both message shapes.

    A notification signed under a guessable nonce is exactly as replayable as a request
    signed under one, and a check that covered only requests would be a hole shaped like
    the message the caller cares least about.
    """
    posted = []
    seen = []
    with capturing_notification_failures(seen):
        await send_one(
            make_config(nonce_factory=lambda: "short"),
            capturing_poster(posted),
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert any("at least 22" in str(e) for _, e in seen)
    assert posted == [], "nothing may reach the wire under a sub-floor nonce"


@pytest.mark.anyio
async def test_a_hardened_policy_opens_with_a_non_exporting_signer():
    config = make_config(
        signer=Signer.from_device(
            "did:example:host-a", "client-key-1", SigningDevice.from_seed(CLIENT_SEED)
        ),
        policy=SignerPolicy.hardened("did:example:host-a"),
    )
    async with mcp_re_http_transport(config, capturing_poster([])) as (read, write):
        assert read is not None and write is not None


@pytest.mark.anyio
async def test_a_hardened_policy_refuses_software_custody():
    """The hardening profile's REFUSAL, which the positive case above cannot witness.

    A route that demands non-exporting custody and opens against an exportable software
    key has granted exactly what the profile exists to deny: the private key is a value
    in this process's memory, so the actor binding it signs proves possession of
    something that can be copied out of the host. The TypeScript twin declares the same
    refusal; this is the Python half.
    """
    config = make_config(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        policy=SignerPolicy.hardened("did:example:host-a"),
    )
    with pytest.raises(McpReError) as ei:
        async with mcp_re_http_transport(config, capturing_poster([])):
            pass
    assert ei.value.wire_code == "mcp-re.actor_binding_failed"


# --- SD-03: a caller that must know its notification was accepted ------------------


@pytest.mark.anyio
async def test_send_notification_verified_raises_when_the_202_does_not_verify():
    """SD-03: neither SDK may treat a notification as delivered until its 202 verifies.

    The TypeScript twin gives its caller that guarantee directly — `send()` awaits the
    whole obligation and throws `NotificationNotAcknowledged`. `ClientSession.
    send_notification()` cannot: it hands the message to an anyio memory stream and
    returns, so the pump on the other side has no caller left to raise to, and reaching
    back through it would mean raising inside the task group that runs every concurrent
    exchange — the remotely-triggerable session kill round 5 removed.

    So the awaited surface is a separate call, and this pins that it fails closed rather
    than reporting a delivery nothing acknowledged.
    """
    from mcp_re_sdk.transport import send_notification_verified

    async def unsigned(method, target_uri, headers, body):
        # A 202 with no signature: transmitted, but nothing acknowledged it.
        return HttpReply(status=202, headers=[], body=b"")

    with pytest.raises(NotificationNotAcknowledged) as raised:
        await send_notification_verified(make_config(), unsigned, "notifications/cancelled")
    assert raised.value.method == "notifications/cancelled"
    assert raised.value.wire_code, "the frozen reason travels with the refusal"


@pytest.mark.anyio
async def test_send_notification_verified_posts_the_signed_notification():
    """It is the same obligation the pump runs, not a second code path: the message is
    signed and POSTed, and only the acknowledgement decides the outcome."""
    from mcp_re_sdk.transport import send_notification_verified

    calls = []

    async def unsigned(method, target_uri, headers, body):
        calls.append((method, target_uri, bytes(body)))
        return HttpReply(status=202, headers=[], body=b"")

    with contextlib.suppress(NotificationNotAcknowledged):
        await send_notification_verified(make_config(), unsigned, "notifications/initialized")

    assert len(calls) == 1, "the notification must actually be transmitted"
    method, target_uri, body = calls[0]
    assert method == "POST"
    assert target_uri == TARGET
    assert json.loads(body)["method"] == "notifications/initialized"
    assert "id" not in json.loads(body), "a notification has no id"
