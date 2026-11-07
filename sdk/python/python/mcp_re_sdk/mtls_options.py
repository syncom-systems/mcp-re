# SPDX-License-Identifier: Apache-2.0
"""The options and the failure of the mTLS connect helper (see :mod:`mcp_re_sdk.mtls`)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from .custody import McpReSdkError

__all__ = ["MtlsOptions", "MtlsTransportError"]

#: Default response ceiling, mirroring the proxy's own ``max_body_bytes``.
_DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

#: Default connect/read/write bound in seconds, mirroring the Rust client's ``ClientLimits``.
_DEFAULT_TIMEOUT = 30.0


class MtlsTransportError(McpReSdkError):
    """The channel failed: handshake refused, timed out, or an over-sized response.

    A LOCAL condition, never an MCP-RE verdict. A proxy that cannot authenticate itself
    is a failed channel, not a failed signature, and it must not be reported as bad
    evidence — nothing was signed, verified, or rejected here.
    """


@dataclass(frozen=True)
class MtlsOptions:
    """The material and bounds for one verifying mTLS client."""

    #: PEM bundle of the ONLY roots trusted to authenticate the proxy. A path, or the PEM
    #: bytes themselves. The system trust store is never added to it.
    server_ca: Union[str, Path, bytes]
    #: PEM path of the client certificate chain presented to the proxy.
    client_cert: Union[str, Path]
    #: PEM path of its private key. May be omitted when the key is in ``client_cert``.
    client_key: Optional[Union[str, Path]] = None
    #: Passphrase for an encrypted ``client_key``.
    client_key_password: Optional[str] = None

    #: The identity the proxy must PROVE, matched against its certificate, and sent as
    #: SNI and in the ``Host`` header. Defaults to the host of the config's ``target_uri``.
    server_name: Optional[str] = None
    #: Where to dial, when that is not ``server_name``'s own address — a load balancer,
    #: a port-forward, a test listener. The identity proven is still ``server_name``.
    connect_address: Optional[Tuple[str, int]] = None

    #: Bound on connect, on each socket operation, and — as an aggregate wall clock — on
    #: reading the whole response, in seconds. ``None`` disables all three, which lets a
    #: stalled peer hold an exchange open indefinitely.
    timeout: Optional[float] = _DEFAULT_TIMEOUT
    #: Response bytes read before failing closed.
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if self.max_response_bytes < 1:
            raise McpReSdkError(
                f"max_response_bytes must be a positive integer, got {self.max_response_bytes!r}"
            )
        if self.timeout is not None and self.timeout <= 0:
            raise McpReSdkError(f"timeout must be positive or None, got {self.timeout!r}")
