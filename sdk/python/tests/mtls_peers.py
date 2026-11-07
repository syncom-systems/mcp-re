# SPDX-License-Identifier: Apache-2.0
"""Real loopback peers for the mTLS helper's tests.

Each peer is a socket speaking real HTTP, read through a real ``http.client.HTTPResponse``.
A fake response object cannot be wrong in the way the one these replaced was, which is why
the evidence for the response-read bounds has to come from here.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path


def server_context(material: Path, cert_stem: str, key_stem: str = None) -> ssl.SSLContext:
    """A TLS server context presenting `cert_stem` and requiring a client certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # The floor the client under test states; a fixture server must not be the weaker end.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        str(material / f"{cert_stem}.crt"), str(material / f"{key_stem or cert_stem}.key")
    )
    # Client-auth required, so a successful round trip proves the client certificate was
    # presented and accepted — not merely that the server was reachable.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(str(material / "ca.crt"))
    return context


def _declared_length(head: bytes) -> int:
    declared = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            declared = int(line.split(b":", 1)[1])
    return declared


def _close_quietly(conn) -> None:
    if conn is None:
        return
    try:
        conn.close()
    except OSError:
        pass


class _LoopbackPeer:
    """A single-connection HTTP peer on loopback; a subclass decides how it answers.

    `sent` counts body bytes actually written, and `completed` says the whole declared body
    went out — so a test can tell a read that ended on its own bound from a peer that
    simply finished.
    """

    #: Whether the request body is read before answering.
    drain_body = True

    def __init__(self, *, content_length, context=None):
        self.content_length = content_length
        self.context = context
        self.sent = 0
        self.completed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _read_head(self, conn):
        """The request head (and whatever body arrived with it); None when the client left."""
        head = b""
        while b"\r\n\r\n" not in head:
            data = conn.recv(4096)
            if not data:
                return None
            head += data
        return head

    def _drain_body(self, conn, head: bytes) -> None:
        declared = _declared_length(head)
        body = head.split(b"\r\n\r\n", 1)[1]
        while len(body) < declared:
            data = conn.recv(4096)
            if not data:
                return
            body += data

    def _read_request(self, conn) -> bool:
        """Read the request; False when the client left before finishing its head."""
        head = self._read_head(conn)
        if head is None:
            return False
        if self.drain_body:
            self._drain_body(conn, head)
        return True

    def _response_head(self) -> bytes:
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"content-type: application/json\r\n"
            b"content-length: " + str(self.content_length).encode() + b"\r\n"
            b"\r\n"
        )

    def _answer(self, conn) -> None:
        raise NotImplementedError

    def _serve(self):
        conn = None
        try:
            conn, _ = self._listener.accept()
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            if self._read_request(conn):
                self._answer(conn)
        except OSError:
            # The client hung up mid-answer, which is the outcome under test.
            pass
        finally:
            _close_quietly(conn)

    def close(self):
        self._listener.close()


class TricklingPeer(_LoopbackPeer):
    """Answers correctly, then feeds the body one byte at a time.

    Slow enough to outlive any aggregate bound worth testing while staying far busier than
    any per-recv inactivity bound. Its trickle budget is finite so a regression fails
    loudly instead of hanging.
    """

    def __init__(self, *, pause=0.01, budget=8.0, content_length=1_000_000, context=None):
        self.pause = pause
        self.budget = budget
        super().__init__(content_length=content_length, context=context)

    def _answer(self, conn):
        conn.sendall(self._response_head())
        end = time.monotonic() + self.budget
        while self.sent < self.content_length and time.monotonic() < end:
            conn.sendall(b"x")
            self.sent += 1
            time.sleep(self.pause)
        self.completed = self.sent >= self.content_length


class PromptPeer(_LoopbackPeer):
    """Answers a whole body at once. The positive mirror.

    Without it every assertion about a bound is satisfied by a reader that refuses
    everything, and a bound that refuses ordinary responses is not a bound.
    """

    def __init__(self, *, payload=b"y" * 4096, context=None):
        self.payload = payload
        super().__init__(content_length=len(payload), context=context)

    def _answer(self, conn):
        conn.sendall(self._response_head() + self.payload)
        self.sent = len(self.payload)
        self.completed = True


class SilentPeer(_LoopbackPeer):
    """Answers, sends a few bytes, and then stops without closing.

    The other half of the composed bound. `read1` returns control to the deadline check
    after every byte a peer sends — so a peer that sends NOTHING is the one case the loop
    cannot observe, and what ends it is the per-recv timeout `http.client` already
    carries. Left unmeasured, that case is where "the read is bounded" quietly becomes
    "the read is bounded while the peer keeps talking".
    """

    drain_body = False

    def __init__(self, *, hold=30.0, context=None):
        self.hold = hold
        super().__init__(content_length=1_000_000, context=context)

    def _answer(self, conn):
        conn.sendall(self._response_head() + b"xxx")
        self.sent = 3
        # Held open and silent. Closing would give the reader an EOF to act on, which
        # is the case that is NOT under test.
        time.sleep(self.hold)
