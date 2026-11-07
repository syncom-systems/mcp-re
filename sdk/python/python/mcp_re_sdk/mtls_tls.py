# SPDX-License-Identifier: Apache-2.0
"""The verifying TLS context, and where one signed request is dialled (see :mod:`mcp_re_sdk.mtls`)."""
from __future__ import annotations

import ssl
from typing import Tuple
from urllib.parse import urlsplit

from .custody import McpReSdkError
from .mtls_options import MtlsOptions

def _ssl_context(options: MtlsOptions) -> ssl.SSLContext:
    """A verifying client context: the configured CA only, hostname checked, mTLS on."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Stated rather than inherited. `PROTOCOL_TLS_CLIENT` sets both today, and a context
    # that silently stopped checking the certificate or the name would still complete a
    # handshake and still carry perfectly verifiable evidence.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        if isinstance(options.server_ca, bytes):
            context.load_verify_locations(cadata=options.server_ca.decode())
        else:
            context.load_verify_locations(cafile=str(options.server_ca))
    except (OSError, ssl.SSLError, ValueError) as e:
        # Named here rather than left to surface at the first handshake, where a bundle
        # that is empty, unreadable, or not PEM at all would present as a server fault.
        raise McpReSdkError(
            f"server_ca has no certificate to authenticate the proxy with: {e}"
        ) from e

    context.load_cert_chain(
        certfile=str(options.client_cert),
        keyfile=str(options.client_key) if options.client_key is not None else None,
        password=options.client_key_password,
    )
    return context


def _origin_form(target_uri: str) -> str:
    """The origin-form request target (path + query) of an absolute ``@target-uri``.

    The signature covers the ABSOLUTE target URI; the request line carries the origin
    form of it. Both sides derive the covered value from their own configuration, so this
    conversion never feeds the signature base — it only routes the request at the peer.
    """
    parts = urlsplit(target_uri)
    if not parts.scheme or not parts.netloc:
        raise McpReSdkError(f"target_uri is not absolute: {target_uri!r}")
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _endpoint(target_uri: str, options: MtlsOptions) -> Tuple[str, int, Tuple[str, int]]:
    """The name to prove, the port, and the address to dial."""
    parts = urlsplit(target_uri)
    if parts.scheme != "https":
        # An http:// target would be signed and sent in the clear. The evidence would
        # still verify, which is exactly why this cannot be left to the deployment.
        raise McpReSdkError(
            f"connect_mtls_http needs an https:// target_uri, got {target_uri!r}"
        )
    server_name = options.server_name or parts.hostname
    if not server_name:
        raise McpReSdkError(f"target_uri has no host to authenticate: {target_uri!r}")
    port = parts.port or 443
    return server_name, port, options.connect_address or (server_name, port)
