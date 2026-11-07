# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for the transport adapter's shutdown (#421) and its bounded
concurrency: closing aborts in-flight work and leaves no correlation state behind, and a
burst cannot exhaust the poster.
"""
import base64

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCNotification  # noqa: E402
from mcp_re_sdk import (  # noqa: E402
    CorrelationStore,
    HttpReply,
    mcp_re_http_transport,
    McpReError,
    McpReSdkError,
    OpaqueBytesProvider,
)
from mcp_re_sdk.transport import _Dispatcher, _pump  # noqa: E402
from transport_fixtures import (  # noqa: E402
    capturing_poster,
    make_config,
    make_request,
    send_one,
    throwing_poster,
)


# --- shutdown (#421) -------------------------------------------------------------
#
# Python's lifecycle IS the `async with` block, so most of the contract holds
# structurally. Mirrors `lifecycle`/shutdown in sdk/typescript/test/transport.test.ts —
# see sdk/PARITY.md for why the two surfaces differ.


@pytest.mark.anyio
async def test_close_aborts_in_flight_work_rather_than_draining_it():
    # Abortive by design, matching the upstream client's rejection of pending requests.
    # It makes NO claim that already-dispatched remote work has stopped.
    started, completed = [], []

    async def slow(method, target_uri, headers, body) -> HttpReply:
        started.append(1)
        await anyio.sleep(5)
        completed.append(1)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(make_config(), slow) as (read, write):
        await write.send(SessionMessage(make_request()))
        await anyio.sleep(0.05)

    assert started == [1], "the exchange must have begun"
    assert completed == [], "in-flight work is aborted, not drained"


@pytest.mark.anyio
async def test_close_aborts_an_in_flight_notification_too():
    # #421 applies to a notification for the same reason it applies to a request: the
    # caller has torn the transport down, and an acknowledgement it will never look at
    # must not hold the close open.
    started, completed = [], []

    async def slow(method, target_uri, headers, body) -> HttpReply:
        started.append(1)
        await anyio.sleep(5)
        completed.append(1)
        return HttpReply(status=202, headers=[], body=b"")

    async with mcp_re_http_transport(make_config(), slow) as (read, write):
        await write.send(
            SessionMessage(
                JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
            )
        )
        await anyio.sleep(0.05)

    assert started == [1], "the notification must have been sent"
    assert completed == [], "in-flight work is aborted, not drained"


@pytest.mark.anyio
async def test_close_refuses_further_work():
    posted = []
    async with mcp_re_http_transport(make_config(), capturing_poster(posted)) as (read, write):
        pass

    # The streams are closed, so a signed request cannot leave a transport the caller has
    # already left. (Broken vs Closed depends on which end shut first; both refuse.)
    with pytest.raises((anyio.ClosedResourceError, anyio.BrokenResourceError)):
        await write.send(SessionMessage(make_request()))
    assert posted == []


@pytest.mark.anyio
async def test_close_delivers_nothing_to_a_caller_that_has_left():
    async with mcp_re_http_transport(make_config(), capturing_poster([])) as (read, write):
        pass

    with pytest.raises((anyio.ClosedResourceError, anyio.EndOfStream)):
        read.receive_nowait()


@pytest.mark.anyio
async def test_close_clears_abandoned_correlation_state():
    # Correlation entries would otherwise outlive the transport that owns them.
    store = CorrelationStore()

    async def slow(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(make_config(), slow, correlation=store) as (read, write):
        await write.send(SessionMessage(make_request()))
        await anyio.sleep(0.05)
        assert len(store) == 1, "the request must be outstanding"

    assert len(store) == 0, "close must clear abandoned correlation state"


@pytest.mark.anyio
async def test_correlation_state_belongs_to_the_transport_not_the_config():
    """Two transports built from one config must not share — or clear — each other's state.

    The config is a value object a caller may reasonably reuse for a second session. When
    the store hung off it, closing either transport reaped the OTHER's outstanding
    requests, and every response still in flight there failed as an unbound response.
    """
    config = make_config()
    first, second = CorrelationStore(), CorrelationStore()

    async def slow(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(config, slow, correlation=second) as (_r2, w2):
        await w2.send(SessionMessage(make_request(id=2)))
        await anyio.sleep(0.05)

        async with mcp_re_http_transport(config, slow, correlation=first) as (_r1, w1):
            await w1.send(SessionMessage(make_request(id=1)))
            await anyio.sleep(0.05)
            assert len(first) == 1 and len(second) == 1

        # The inner transport closed. The outer one's request is still outstanding.
        assert len(first) == 0, "the closed transport clears its own state"
        assert len(second) == 1, "and only its own"


@pytest.mark.anyio
async def test_a_failed_exchange_does_not_leave_its_correlation_entry_outstanding():
    """Anything that can fail an exchange is remotely triggerable, so a leak is a lever.

    The entry is recorded before the POST and consumed by the response. A failure in
    between produces no response to consume it, so without an explicit retirement the
    store grows by one per failed request for the life of the session.
    """
    store = CorrelationStore()

    for exc in (
        ConnectionResetError("reset"),
        McpReError("mcp-re.replay_detected"),
        ValueError("mcp-re.response_sig_invalid"),
    ):
        await send_one(make_config(), throwing_poster(exc), make_request(), correlation=store)

    assert len(store) == 0, f"{exc!r} left its entry outstanding"


# --- concurrency -----------------------------------------------------------------
#
# Mirrors `concurrency` in sdk/typescript/test/transport.test.ts: the two SDKs must agree
# on how many exchanges may be in flight, not just on the bytes they emit.


def _gated_poster(peak: dict, hold: float = 0.05):
    """Count how many posts are in flight at once."""
    peak.setdefault("now", 0)
    peak.setdefault("max", 0)

    async def post(method, target_uri, headers, body) -> HttpReply:
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        await anyio.sleep(hold)
        peak["now"] -= 1
        raise McpReError("mcp-re.replay_detected")  # stop before native verification

    return post


async def _drive(config, poster, count: int):
    """Send `count` requests at once and wait for all their replies."""
    read_writer, read_stream = anyio.create_memory_object_stream(64)
    write_stream, write_reader = anyio.create_memory_object_stream(64)
    for i in range(count):
        await write_stream.send(SessionMessage(make_request(id=i)))
    await write_stream.aclose()
    await _pump(_Dispatcher(config, poster, read_writer), write_reader)

    replies = []
    for _ in range(count):
        try:
            replies.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break
    return replies


@pytest.mark.anyio
async def test_exchanges_run_concurrently_rather_than_head_of_line_blocking():
    # MCP is not lock-step. Awaiting each exchange before reading the next request would
    # make one slow tool call block every other request on the session.
    peak = {}
    replies = await _drive(make_config(), _gated_poster(peak), 4)

    assert peak["max"] == 4, f"exchanges serialized (peak {peak['max']} of 4)"
    assert len(replies) == 4, "every request must still get its reply"


@pytest.mark.anyio
async def test_concurrency_is_bounded_so_a_burst_cannot_exhaust_the_poster():
    # Each in-flight exchange holds a connection and a signing operation (a KMS round
    # trip under non-exporting custody); unbounded fan-out would exhaust either.
    peak = {}
    replies = await _drive(make_config(max_concurrent_exchanges=2), _gated_poster(peak), 6)

    assert peak["max"] == 2, f"the bound was not honoured (peak {peak['max']}, limit 2)"
    assert len(replies) == 6, "bounding must delay a request, never drop it"


@pytest.mark.parametrize("bad", [0, -1, 2.5, True, None, "8"])
def test_an_invalid_bound_is_refused_rather_than_deadlocking(bad):
    """A bound of 0 does not throttle — it deadlocks.

    Every sender waits for a slot that can never be released, and the session hangs in
    silence. Nothing about that is recoverable at runtime, so it must be refused where
    the value enters. `True` is in here because `isinstance(True, int)` is True in
    Python: a bool would otherwise sail through as a bound of 1.
    """
    with pytest.raises(McpReSdkError, match="positive integer"):
        make_config(max_concurrent_exchanges=bad)


def test_a_valid_bound_is_accepted():
    assert make_config(max_concurrent_exchanges=1).max_concurrent_exchanges == 1


@pytest.mark.anyio
async def test_every_concurrent_reply_is_correlated_to_its_own_request():
    # Concurrency must not let one request's outcome land on another's id.
    replies = await _drive(make_config(), _gated_poster({}), 4)
    assert sorted(r.message.id for r in replies) == [0, 1, 2, 3]


@pytest.mark.anyio
async def test_authorization_bindings_reach_the_core_which_digests_the_real_bytes():
    # bind-not-interpret: the provider supplies the artifact; the core digests it. The
    # bytes themselves must never appear in the evidence.
    import base64

    material = b"human-approval-record"
    calls = []
    config = make_config(authorization=[OpaqueBytesProvider("human-approval", material)])
    await send_one(config, capturing_poster(calls), make_request())

    evidence = calls[0]["body"].decode()
    assert "human-approval" in evidence
    assert "human-approval-record" not in evidence
    assert base64.urlsafe_b64encode(material).decode().rstrip("=") not in evidence
