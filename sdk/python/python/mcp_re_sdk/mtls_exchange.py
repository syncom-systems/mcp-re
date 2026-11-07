# SPDX-License-Identifier: Apache-2.0
"""One request and one bounded response over one fresh verified connection (see :mod:`mcp_re_sdk.mtls`)."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from typing import NamedTuple, Sequence, Tuple

from .mtls_options import MtlsOptions, MtlsTransportError
from .transport import HttpReply

#: Headers this transport owns because it owns the framing. A caller that could set one
#: could desynchronise the message boundary from what the peer parses — the classic
#: request-smuggling shape — so supplying one fails closed rather than being silently
#: dropped or duplicated. Same list the Rust client refuses.
_TRANSPORT_OWNED_HEADERS = frozenset({"host", "content-length", "connection", "transfer-encoding"})

class _Peer(NamedTuple):
    """The proxy one exchange talks to: the name to prove, the port, the address to dial,
    and the verifying context to prove it with."""

    server_name: str
    port: int
    dial: Tuple[str, int]
    context: ssl.SSLContext


class _Request(NamedTuple):
    """One signed request, exactly as it was signed."""

    method: str
    path: str
    headers: Sequence[Tuple[str, str]]
    body: bytes


class _MtlsConnection(http.client.HTTPSConnection):
    """An HTTPS connection that dials one address and proves a possibly different name.

    ``HTTPSConnection`` derives the SNI and the certificate-name check from the address
    it dials, which collapses "where the endpoint answers" into "who it is allowed to
    be". Keeping them apart is what lets a client reach the proxy through a load
    balancer, a port-forward, or a pinned IP while still refusing any certificate not
    valid for the configured ``server_name``.
    """

    def __init__(self, peer: _Peer, timeout):
        super().__init__(peer.server_name, peer.port, context=peer.context, timeout=timeout)
        self._dial = peer.dial

    def connect(self) -> None:
        sock = socket.create_connection(self._dial, self.timeout)
        # `server_hostname` is BOTH the SNI sent and the name the certificate is checked
        # against, and it is `self.host` — the configured identity — not `self._dial`.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


#: The most this reader will take from one underlying read. An upper bound on a `read1`,
#: never a fill-to size: `read1` returns what one read produced, which is what lets the
#: deadline be consulted between reads rather than after the whole body.
_READ_CHUNK_BYTES = 64 * 1024


def _read_bounded(response, options: MtlsOptions) -> bytes:
    """Read the response body under BOTH bounds: the byte ceiling and a wall clock.

    ``options.timeout`` on the socket is a PER-RECV bound, and a per-recv bound bounds
    nothing on its own: every byte that arrives re-arms it, so a peer trickling just under
    it extends the total read without limit. Each stalled exchange also holds a
    ``CapacityLimiter`` slot, so ``max_concurrent_exchanges`` of them wedge the whole
    client session with no error and no timeout. The Rust client leg this module mirrors
    caps total read time at the same value (MCPS-093 ``read_response_bounded``); this is
    that cap.

    **``read1``, never ``read``, is what keeps the check reachable.**
    ``HTTPResponse.read(n)`` fills to ``n``, so one call absorbs an unbounded number of
    underlying reads and the loop below does not run again until it returns — which is
    exactly how a bound written this way came to be advertised and not enforced.
    ``read1(n)`` returns what ONE underlying read produced, chunked-framing decode
    included, so the deadline is consulted between underlying reads and, once it has
    passed, **no NEW underlying read is begun**.

    **The read already in progress is bounded by the per-recv timeout**, which
    ``http.client`` already carries from ``options.timeout``. One underlying read may
    straddle the deadline — a peer that goes silent mid-read is not observable from a check
    made between reads — and that final stall is what the per-recv bound ends.

    So the cap is the aggregate deadline PLUS AT MOST ONE per-recv timeout: at most
    ``2 * options.timeout`` under the single value a deployment sets. It is not an exact
    wall-clock bound and is not documented as one. Narrowing the socket's own timeout to
    the time remaining would tighten it to exactly the deadline, and it is deliberately NOT
    done: with ``Connection: close`` — the framing this transport sends — ``http.client``
    hands the connection to the response and closes the socket object, so the only handle
    left is a private attribute of the response's file object. A bound that reaches through
    a foreign object's internals is the kind of dependency this SDK would have to register
    as a premise, and the composed bound above needs none.

    ``timeout is None`` disables the per-recv bound, and disables this one too — that knob
    means "no bound", and honouring it on one of the two would be a different setting
    wearing the same name.

    One byte past ``max_response_bytes`` is enough to know the ceiling was exceeded, and
    stops a hostile length from being allocated to find out.
    """
    ceiling = options.max_response_bytes
    deadline = None if options.timeout is None else time.monotonic() + options.timeout
    chunks: list[bytes] = []
    size = 0
    while size <= ceiling:
        if deadline is not None and time.monotonic() >= deadline:
            raise MtlsTransportError(
                f"the aggregate response read exceeded {options.timeout}s "
                f"(slow-loris trickle)"
            )
        want = min(_READ_CHUNK_BYTES, ceiling + 1 - size)
        chunk = response.read1(want)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    if size > ceiling:
        raise MtlsTransportError(f"response exceeded max_response_bytes ({ceiling})")
    return b"".join(chunks)


def _refuse_transport_owned_headers(headers: Sequence[Tuple[str, str]]) -> None:
    for name, _ in headers:
        if name.lower() in _TRANSPORT_OWNED_HEADERS:
            raise MtlsTransportError(
                f"{name.lower()} is set by the transport and must not be signed into a request"
            )


def _send(connection: _MtlsConnection, request: _Request) -> None:
    # Built header by header rather than through `request(headers=...)`, which takes a
    # mapping and would collapse a repeated header name — dropping bytes that the
    # RFC 9421 signature covers.
    connection.putrequest(request.method, request.path, skip_accept_encoding=True)
    connection.putheader("Content-Length", str(len(request.body)))
    # Single request per connection, as the proxy frames it.
    connection.putheader("Connection", "close")
    for name, value in request.headers:
        # `putheader` refuses a CR/LF in a value, so a header that would split the
        # request into two never reaches the socket.
        connection.putheader(name, value)
    connection.endheaders(request.body)


def _receive(connection: _MtlsConnection, options: MtlsOptions) -> HttpReply:
    response = connection.getresponse()
    payload = _read_bounded(response, options)
    # Lowercased and in wire order: the profile matches header names
    # case-insensitively, and the signature base is built from what arrived.
    return HttpReply(
        status=response.status,
        headers=[(name.lower(), value) for name, value in response.getheaders()],
        body=payload,
    )


def _exchange(peer: _Peer, options: MtlsOptions, request: _Request) -> HttpReply:
    """One blocking request/response over one fresh verified connection."""
    _refuse_transport_owned_headers(request.headers)
    connection = _MtlsConnection(peer, options.timeout)
    try:
        _send(connection, request)
        return _receive(connection, options)
    except ssl.SSLError as e:
        # The proxy did not authenticate: an untrusted chain, a wrong identity, an
        # expired certificate. A failed channel, never a failed signature.
        raise MtlsTransportError(f"the proxy failed TLS authentication: {e}") from e
    except (socket.timeout, TimeoutError) as e:
        raise MtlsTransportError(f"the exchange timed out after {options.timeout}s: {e}") from e
    except OSError as e:
        raise MtlsTransportError(f"the connection failed: {e}") from e
    finally:
        connection.close()
