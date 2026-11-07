# SPDX-License-Identifier: Apache-2.0
"""Freshness inputs for one signed request: the clock and the anti-replay nonce.

The nonce floor is enforced where a nonce is EMITTED, so a caller-supplied
``nonce_factory`` cannot weaken replay protection while every signature still verifies.
"""
from __future__ import annotations

import secrets
import time
from typing import Callable

from .custody import McpReSdkError


#: Minimum characters in an anti-replay nonce. 128 bits base64url-encodes to 22
#: characters, which is what both SDKs' default generators produce — so this floor
#: never constrains the default path. It constrains an OVERRIDE: ``nonce_factory`` is
#: caller-supplied and was accepted unchecked, so a factory returning a counter, a
#: timestamp, or a truncated value silently weakened replay protection for every
#: request while every signature still verified.
MIN_NONCE_CHARS = 22


def _default_nonce() -> str:
    # 128 bits from the OS CSPRNG: the freshness window rejects a repeat, so the only
    # requirement here is that a collision is not reachable in practice.
    return secrets.token_urlsafe(16)


def _checked_nonce(factory: Callable[[], str]) -> str:
    """Draw a nonce and refuse a sub-floor one, at SIGN time.

    Fails closed rather than signing: a request signed under a guessable nonce is
    accepted by the verifier and is exactly what the replay window cannot save you
    from. Enforced only where a nonce is EMITTED — the accepted wire language is
    unchanged, so this needs no cross-implementation coordination and no fixture
    regeneration.
    """
    nonce = factory()
    if not isinstance(nonce, str) or len(nonce) < MIN_NONCE_CHARS:
        # `McpReSdkError`, not `McpReError`: this is a LOCAL misconfiguration, and
        # `McpReError.wire_code` is documented as a frozen `mcp-re.*` token a caller can
        # branch on without parsing prose. Raising it with an English sentence in that
        # position invented a token, and the sentence then travelled as one.
        raise McpReSdkError(
            f"mcp-re-sdk: nonce_factory returned {len(nonce) if isinstance(nonce, str) else type(nonce).__name__} "
            f"characters; a nonce must be at least {MIN_NONCE_CHARS} (128 bits base64url)"
        )
    return nonce


def _default_clock() -> int:
    return int(time.time())
