# SPDX-License-Identifier: Apache-2.0
"""The mTLS connect helper against a real TLS server (#413 slice 2).

The transport adapter's HTTP leg used to be entirely the caller's, which meant the one
part of the deployment that decides whether the channel is authenticated at all had no
shipped implementation and no test. This covers it end-to-end: a genuine TLS handshake
against a server holding a real certificate, with client-auth required.

The interesting cases are the refusals. A response signature verifies identically whether
or not the channel proved who produced it, so nothing above this layer can notice a
connection that was never authenticated — which is exactly why *these* assertions carry
the weight:

- a certificate from a CA the client does not trust is refused;
- a certificate the trusted CA *did* sign, for a DIFFERENT name, is refused.

The second is the one a chain-of-trust-only client passes and should not. The identity
proven is the configured ``server_name``, not wherever the socket happened to land, so
every test here dials loopback while requiring `mcp-re-proxy.test`.

Mirrors ``sdk/typescript/test/mtls.test.ts`` — same generated material, same assertions.
"""
import contextlib
import http.client
import http.server
import sys
import threading
import time
from pathlib import Path

import anyio
import pytest

pytest.importorskip("mcp", reason="the mtls helper builds on the transport adapter")
pytest.importorskip("cryptography", reason="the test material is minted with cryptography")

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from gen_mtls_test_material import SERVER_NAME, generate  # noqa: E402

from mcp_re_sdk import McpReConfig, McpReSdkError, Signer  # noqa: E402
from mcp_re_sdk.mtls import MtlsOptions, MtlsTransportError, mtls_poster  # noqa: E402
from mcp_re_sdk.mtls_exchange import _read_bounded  # noqa: E402
from mtls_peers import PromptPeer, SilentPeer, TricklingPeer, server_context  # noqa: E402

CLIENT_SEED = bytes([11]) * 32


@pytest.fixture(scope="module")
def material(tmp_path_factory):
    """Throwaway X.509, minted once per run. Never committed — see the generator."""
    return generate(tmp_path_factory.mktemp("mtls"))


class _Handler(http.server.BaseHTTPRequestHandler):
    """Echo back what arrived, so a test can assert the request survived the channel."""

    #: Set per-server: how many body bytes to reply with.
    reply_bytes = 16
    #: Extra header pairs to emit, in order, duplicates included.
    extra_headers: list = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        body = b"x" * self.reply_bytes
        self.send_response(200)
        self.send_header("content-type", "application/json")
        for name, value in self.extra_headers:
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # a test server that narrates every request drowns the failure output


@contextlib.contextmanager
def _serving(material: Path, cert_stem: str, key_stem: str = None, **handler_attrs):
    """A TLS server on loopback presenting `cert_stem`, requiring a client certificate."""
    handler = type("_Bound", (_Handler,), dict(handler_attrs))
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    server.socket = server_context(material, cert_stem, key_stem).wrap_socket(
        server.socket, server_side=True
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()


def _config(port: int, **over) -> McpReConfig:
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=f"https://{SERVER_NAME}:{port}/mcp",
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url="x" * 43,
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
    )
    args.update(over)
    return McpReConfig(**args)


def _options(material: Path, **over) -> MtlsOptions:
    args = dict(
        server_ca=material / "ca.crt",
        client_cert=material / "client.crt",
        client_key=material / "client.key",
        timeout=10,
    )
    args.update(over)
    return MtlsOptions(**args)


async def _post(material: Path, server, options_over=None, headers=None):
    port = server.server_address[1]
    config = _config(port)
    options = _options(material, connect_address=("127.0.0.1", port), **(options_over or {}))
    poster = mtls_poster(config, options)
    return await poster("POST", config.target_uri, headers or [], b"{}")


@pytest.mark.anyio
async def test_a_signed_request_round_trips_over_a_verified_channel(material):
    """The happy path — and the only one that says the helper is usable at all."""
    with _serving(material, "server") as server:
        reply = await _post(material, server, headers=[("content-type", "application/json")])

    assert reply.status == 200
    assert reply.body == b"x" * 16
    # Lowercased, as the profile matches header names: the signature base is built from
    # what arrived, so the reply's headers are handed back verbatim in wire order.
    assert ("content-type", "application/json") in reply.headers


@pytest.mark.anyio
async def test_a_certificate_from_an_untrusted_root_is_refused(material):
    """Chain-of-trust: the certificate is perfectly valid — for the wrong root."""
    with _serving(material, "foreign_server") as server:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server)
    assert "authentication" in str(raised.value)


@pytest.mark.anyio
async def test_a_certificate_for_a_different_name_is_refused(material):
    """Identity: the TRUSTED CA signed this one — for somewhere else.

    A client that verified only the chain would accept it. That is the failure this
    assertion exists for: the whole point of naming the server is that any certificate
    the CA ever issued is not automatically this server's.
    """
    with _serving(material, "wrongname") as server:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server)
    assert "authentication" in str(raised.value)


@pytest.mark.anyio
async def test_an_oversized_response_is_refused(material):
    """A ceiling that fails closed, rather than buffering whatever the peer sends."""
    with _serving(material, "server", reply_bytes=4096) as server:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server, options_over={"max_response_bytes": 1024})
    assert "max_response_bytes" in str(raised.value)


@pytest.mark.anyio
async def test_a_repeated_response_header_is_not_folded(material):
    """Wire order, duplicates intact: the RFC 9421 signature base is built from these.

    A reader that folded repeats into one value would reconstruct a different base than
    the server signed, and the response would fail verification for a reason that has
    nothing to do with the evidence.
    """
    repeats = [("x-repeat", "one"), ("x-repeat", "two")]
    with _serving(material, "server", extra_headers=repeats) as server:
        reply = await _post(material, server)
    assert [v for k, v in reply.headers if k == "x-repeat"] == ["one", "two"]


@pytest.mark.anyio
async def test_a_transport_owned_header_is_refused(material):
    """Framing belongs to the transport. A caller-set `content-length` desynchronises the
    message boundary from what the peer parses — the request-smuggling shape."""
    with _serving(material, "server") as server:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server, headers=[("Content-Length", "9999")])
    assert "content-length" in str(raised.value)


def test_a_plaintext_target_is_refused(material):
    """An http:// target would be signed and sent in the clear, and the evidence would
    still verify — so this cannot be left to the deployment to notice."""
    with pytest.raises(McpReSdkError) as raised:
        mtls_poster(_config(443, target_uri="http://mcp-re-proxy.test/mcp"), _options(material))
    assert "https://" in str(raised.value)


@pytest.mark.anyio
async def test_connect_mtls_http_opens_a_session_transport_over_the_channel(material):
    """The one-call form: the adapter, with its HTTP leg already built and verified.

    The reply here is not signed evidence, so the exchange fails closed — which is the
    point. It proves the composition reached the network and came back through the
    adapter's verification, rather than that a stub returned something agreeable.
    """
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCRequest

    from mcp_re_sdk import connect_mtls_http

    with _serving(material, "server") as server:
        port = server.server_address[1]
        config = _config(port)
        options = _options(material, connect_address=("127.0.0.1", port))
        async with connect_mtls_http(config, options) as (read, write):
            await write.send(
                SessionMessage(JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/list", params={}))
            )
            message = (await read.receive()).message

    assert message.error is not None, "an unsigned reply must never read as a result"


def test_a_ca_bundle_may_be_supplied_as_pem_bytes(material):
    """Material does not have to be on disk — a deployment may hold it in a secret store
    and never write it out."""
    poster = mtls_poster(
        _config(443), _options(material, server_ca=(material / "ca.crt").read_bytes())
    )
    assert callable(poster)


@pytest.mark.parametrize(
    "over, expected",
    [
        ({"max_response_bytes": 0}, "max_response_bytes"),
        ({"timeout": 0}, "timeout"),
    ],
)
def test_a_bound_that_would_refuse_everything_is_refused(material, over, expected):
    """Zero is not a degenerate throttle: a zero ceiling refuses every reply and a zero
    timeout every connection, silently, as if every server were hostile."""
    with pytest.raises(McpReSdkError) as raised:
        _options(material, **over)
    assert expected in str(raised.value)


def test_a_relative_target_is_refused(material):
    """`@target-uri` is absolute by construction; a relative one has no host to
    authenticate and nothing to dial."""
    with pytest.raises(McpReSdkError):
        mtls_poster(_config(443, target_uri="/mcp"), _options(material))


def test_an_empty_ca_bundle_is_refused(material, tmp_path):
    """An empty bundle loads without error and then trusts nothing, so every connection
    fails at the handshake looking like a server fault."""
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    with pytest.raises(McpReSdkError) as raised:
        mtls_poster(_config(443), _options(material, server_ca=empty))
    assert "no certificate" in str(raised.value)


# --- the aggregate response-read bound --------------------------------------------
#
# MEASURED AGAINST A REAL PEER (`mtls_peers`), and the reason is the defect this section
# replaces. The control here used to drive `_read_bounded` with a fake whose `read(n)`
# returned ONE byte per call. Production `http.client.HTTPResponse.read(n)` fills to `n`,
# so the fake had the short-read semantics the real object lacks: in the test the loop's
# deadline check was reached after every byte, and against a real peer it was not reached
# at all until the whole body had arrived. The control could not fail (R9-C094) and the
# property it claimed was false (R9-C010).
#
# So the peers are real sockets speaking real HTTP, read through a real `HTTPResponse`.
# The trickling one sends a valid response head, then body bytes frequently enough never
# to trip an ordinary per-recv inactivity bound, for longer than the aggregate bound under
# test. Its trickle budget is finite so a regression fails loudly instead of hanging, and
# the assertions distinguish "the deadline fired" from "the peer stopped on its own".


@contextlib.contextmanager
def _real_response(peer, *, socket_timeout):
    """A real `http.client.HTTPResponse` from `peer`; the connection and the peer are
    closed on the way out.

    The connection's own timeout is the PER-RECV bound. Every test below sets it far
    larger than the aggregate bound under test, so nothing here can pass because the
    per-recv bound fired: what terminates the read is the aggregate deadline or nothing.
    """
    connection = http.client.HTTPConnection("127.0.0.1", peer.port, timeout=socket_timeout)
    try:
        connection.request("POST", "/mcp", body=b"{}", headers={"content-length": "2"})
        yield connection.getresponse()
    finally:
        connection.close()
        peer.close()


def _bounds(*, timeout, ceiling) -> MtlsOptions:
    """Options whose only live fields are the two bounds under test."""
    return MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=timeout, max_response_bytes=ceiling
    )


def test_the_aggregate_read_deadline_holds_against_a_real_trickling_peer():
    """The aggregate bound terminates a trickle the per-recv bound never notices.

    The peer sends a byte every 10ms against a 5s per-recv bound, so the socket is never
    idle long enough to time out; the only thing that can end this read is the aggregate
    deadline. Remove that enforcement and the read runs for the peer's whole budget and
    this test goes red — which is the property the fake it replaced could not have.
    """
    peer = TricklingPeer(pause=0.01, budget=8.0)
    with _real_response(peer, socket_timeout=5.0) as response:
        started = time.monotonic()
        with pytest.raises(MtlsTransportError) as raised:
            _read_bounded(response, _bounds(timeout=0.5, ceiling=1024 * 1024))
        elapsed = time.monotonic() - started

    assert "aggregate response read" in str(raised.value)
    # It fired ON the deadline: not before it, and nowhere near the peer's 8s budget. An
    # exchange that ended because the peer stopped would land at the budget, not here.
    assert 0.4 <= elapsed < 3.0, f"the aggregate deadline did not bound the read ({elapsed:.2f}s)"
    assert not peer.completed, "the peer finished its body; this measured nothing"
    assert peer.sent > 1, "the peer never trickled; the read stalled rather than progressing"


def test_the_full_mtls_path_bounds_a_trickling_peer(material):
    """The same property through the shipped poster, over real TLS.

    `_read_bounded` is reached from exactly one place, and it is this one. Here the
    aggregate and per-recv bounds are the single `options.timeout` a deployment sets, so
    what is measured is the configuration a caller actually writes.
    """
    peer = TricklingPeer(pause=0.01, budget=8.0, context=server_context(material, "server"))

    poster = mtls_poster(
        _config(peer.port),
        _options(material, timeout=0.6, connect_address=("127.0.0.1", peer.port)),
    )
    started = time.monotonic()
    try:
        with pytest.raises(MtlsTransportError) as raised:
            anyio.run(poster, "POST", f"https://{SERVER_NAME}:{peer.port}/mcp", [], b"{}")
        elapsed = time.monotonic() - started
    finally:
        peer.close()

    assert "aggregate response read" in str(raised.value)
    assert elapsed < 4.0, f"the shipped path did not bound the read ({elapsed:.2f}s)"
    assert not peer.completed, "the peer finished its body; this measured nothing"


def test_a_peer_that_goes_silent_is_ended_by_the_per_recv_bound():
    """The composed bound's worst case, measured rather than asserted.

    A silent peer is invisible to a deadline checked between reads, so this is the half
    the per-recv timeout owns. The whole read still ends within the stated worst case —
    the aggregate deadline plus one per-recv stall — instead of holding an exchange and
    its concurrency slot until the peer feels like closing.
    """
    peer = SilentPeer(hold=30.0)
    with _real_response(peer, socket_timeout=0.5) as response:
        started = time.monotonic()
        with pytest.raises((MtlsTransportError, TimeoutError, OSError)):
            _read_bounded(response, _bounds(timeout=0.5, ceiling=1024 * 1024))
        elapsed = time.monotonic() - started

    # Bounded by `2 * timeout` in the worst case, and nowhere near the peer's 30s hold.
    assert elapsed < 2.0, f"a silent peer held the read open ({elapsed:.2f}s)"


def test_a_response_inside_both_bounds_still_reads_whole():
    """The bound refuses a trickle, not an ordinary reply — measured on the same peer."""
    with _real_response(PromptPeer(payload=b"hello world"), socket_timeout=5.0) as response:
        assert _read_bounded(response, _bounds(timeout=30.0, ceiling=64)) == b"hello world"


def test_the_byte_ceiling_still_fails_closed_one_byte_past_it():
    """The two bounds are independent: the ceiling holds with the clock nowhere near."""
    with _real_response(PromptPeer(payload=b"y" * 65), socket_timeout=5.0) as response:
        with pytest.raises(MtlsTransportError) as raised:
            _read_bounded(response, _bounds(timeout=30.0, ceiling=64))
    assert "max_response_bytes" in str(raised.value)


def test_no_timeout_means_no_aggregate_bound_either():
    """``timeout=None`` is the documented "no bound" knob. Honouring it on one of the two
    bounds and not the other would be a different setting wearing the same name.

    Measured on the prompt peer: with no deadline the read still completes, and nothing
    narrows the socket's own timeout — there is no remaining time to narrow it to.
    """
    with _real_response(PromptPeer(payload=b"ok"), socket_timeout=5.0) as response:
        assert _read_bounded(response, _bounds(timeout=None, ceiling=64)) == b"ok"
