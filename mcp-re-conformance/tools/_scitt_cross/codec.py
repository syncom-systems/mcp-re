# SPDX-License-Identifier: Apache-2.0
"""Base64url and the COSE Sig_structure, written from the RFC text."""

from __future__ import annotations

import base64

import cbor2


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 §4.4: ["Signature1", protected, external_aad, payload]."""
    return cbor2.dumps(["Signature1", protected, b"", payload])
