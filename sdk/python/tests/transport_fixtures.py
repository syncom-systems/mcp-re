# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the transport adapter's offline tests: a minimal config, an
injected poster, and a pump that returns what the session side received."""

import contextlib

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCRequest  # noqa: E402
from mcp_re_sdk import McpReConfig, McpReError, Signer  # noqa: E402
from mcp_re_sdk.transport import _Dispatcher, _pump  # noqa: E402

CLIENT_SEED = bytes([11]) * 32
TARGET = "https://proxy.internal:8600/mcp"
#: The `server-key-1` root issuer of `sdk/fixtures/delegated_response_replay.json`, so the
#: anchor these tests carry is the one the recorded session actually verifies against.
ISSUER_PUBKEY = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"


def drain(read_stream) -> list:
    """Everything already delivered to the session side of a memory stream."""
    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            return out


def make_config(**over) -> McpReConfig:
    """The minimum a config can carry: every optional knob left to its default, so the
    default side of each branch is what runs."""
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=TARGET,
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url=ISSUER_PUBKEY,
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
    )
    args.update(over)
    return McpReConfig(**args)


def make_request(method="tools/list", id=7, params=None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params or {})


def throwing_poster(exc):
    async def post(method, target_uri, headers, body):
        raise exc

    return post


def capturing_poster(calls):
    async def post(method, target_uri, headers, body):
        calls.append({"headers": list(headers), "body": body})
        # Stop before native verification: this test is about what went out.
        raise McpReError("mcp-re.replay_detected")

    return post


async def send_one(config, poster, message, correlation=None):
    """Drive one message through the pump and collect what it hands the session."""
    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    await write_stream.send(SessionMessage(message))
    await write_stream.aclose()
    await _pump(_Dispatcher(config, poster, read_writer, correlation), write_reader)

    return drain(read_stream)


@contextlib.contextmanager
def capturing_notification_failures(sink: list):
    """Capture undeliverable outbound messages instead of printing them.

    Neither a notification nor a refused client->server response has a reply channel, so
    this hook is the only place either outcome is observable — which is exactly why it
    exists rather than the failure being swallowed.
    """
    import mcp_re_sdk.transport as t

    previous = t.on_notification_failure
    t.on_notification_failure = lambda method, error: sink.append((method, error))
    try:
        yield
    finally:
        t.on_notification_failure = previous
