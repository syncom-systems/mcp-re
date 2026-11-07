# SPDX-License-Identifier: Apache-2.0
"""The mTLS connect helper (ADR-MCPS-044 §client obligation).

The transport adapter takes its HTTP leg as an injected ``poster`` so that layer stays
transport-agnostic and testable. This module builds the leg a real deployment needs: a
**verifying** mutual-TLS connection to ``mcp-re-proxy``.

    async with connect_mtls_http(config, options) as (read, write):
        async with ClientSession(read, write) as session:
            await session.call_tool("read_file", {"path": "/etc/hosts"})

It mirrors the Rust client leg (``mcp_re_transport::remote::MtlsRemoteTransport``), and
the properties that matter are the same ones:

- **only the configured CA authenticates the proxy.** The system trust store is never
  consulted, so a certificate from any other public or corporate root is refused.
- **the server's identity is proven, not assumed.** The certificate must be valid for
  ``server_name`` — which is what the address is dialled for, not merely where it
  answered.
- **a client certificate is presented**, for the proxy's own binding check.
- **one connection per exchange**, matching the proxy's framing.
- **every bound fails closed**: a connect/read that stalls past ``timeout``, or a
  response past ``max_response_bytes``, raises rather than hanging or allocating without
  bound. ``timeout`` is BOTH the per-socket bound and an aggregate wall-clock bound on
  reading the response, because the first alone bounds nothing: every byte re-arms it,
  so a peer trickling under it holds an exchange — and its concurrency slot —
  indefinitely.

There is no way to turn verification off. A helper with a ``verify=False`` knob is how
mTLS deployments quietly become TLS-shaped plaintext, and the evidence layer above it
cannot detect that — a response signature verifies identically whether or not the channel
proved who produced it.

The signed request is carried unchanged: MCP-RE's evidence lives in the headers and body
(RFC 9421 ``Signature``/``Signature-Input``, RFC 9530 ``Content-Digest``), so this must
transmit exactly what was signed and hand back exactly what arrived.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import anyio

from .mtls_exchange import _exchange, _Peer, _Request
from .mtls_options import MtlsOptions as MtlsOptions
from .mtls_options import MtlsTransportError as MtlsTransportError
from .mtls_tls import _endpoint, _origin_form, _ssl_context
from .transport import HttpReply, McpReConfig, Poster, mcp_re_http_transport

__all__ = ["MtlsOptions", "MtlsTransportError", "connect_mtls_http", "mtls_poster"]


def mtls_poster(config: McpReConfig, options: MtlsOptions) -> Poster:
    """A :data:`~mcp_re_sdk.transport.Poster` that sends each signed request over one
    verifying mTLS connection.

    The TLS material is loaded once, here, so bad material fails at construction rather
    than on the first request. Use this directly to compose the connection with an
    existing transport; :func:`connect_mtls_http` is the one-call form.
    """
    context = _ssl_context(options)
    peer = _Peer(*_endpoint(config.target_uri, options), context)

    async def post(method: str, target_uri: str, headers, body: bytes) -> HttpReply:
        # `http.client` is blocking, so the exchange runs on a worker thread. Abandoning
        # it on cancellation is the same claim `ConnectionClosed` already makes: a
        # cancelled exchange says nothing about whether the request arrived or what the
        # server did with it — only that this client will not process an answer.
        request = _Request(method, _origin_form(target_uri), list(headers), body)
        return await anyio.to_thread.run_sync(_exchange, peer, options, request, abandon_on_cancel=True)

    return post


@asynccontextmanager
async def connect_mtls_http(config: McpReConfig, options: MtlsOptions, **kwargs):
    """The transport adapter over a verifying mTLS connection to the proxy.

    Yields the ``(read_stream, write_stream)`` pair ``mcp.ClientSession`` expects, exactly
    as :func:`~mcp_re_sdk.transport.mcp_re_http_transport` does — this only supplies the
    HTTP leg. Remaining keyword arguments are passed through to it.
    """
    async with mcp_re_http_transport(config, mtls_poster(config, options), **kwargs) as streams:
        yield streams
