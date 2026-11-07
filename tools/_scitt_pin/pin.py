# SPDX-License-Identifier: Apache-2.0
"""The pin artifact and the commitments an existing pin holds."""

from __future__ import annotations

import datetime
from typing import NamedTuple

SCHEMA = "mcp-re-scitt-service-trust-pin/v1"

# The two service properties a pin records verbatim. The tokens are the serialized form
# `ScittServiceTrustPin` reads (`ReceiptPositionProfile` and `StatementLeafProfile`), so
# a value this tool accepts is a value the verifier accepts.
POSITION_PROFILES = ("unbound", "bound")
LEAF_PROFILES = ("statement-bytes", "statement-digest", "sig-structure-digest")

# What a pin commits a verifier to: the key, and the two profiles it verifies under.
# Changing any of them changes which receipts verify — a weaker position profile lets a
# relayer restate a receipt's position — so each one is replaced only with --replace-pin.
PIN_COMMITMENTS = (
    ("public_key_thumbprint", "key"),
    ("leaf_profile", "leaf profile"),
    ("position_profile", "position profile"),
)


class Discovered(NamedTuple):
    """What one discovery fetch established: the key, and where it came from."""

    kid: str | None
    fields: dict
    uri: str
    document_digest: str


def replaced_pin_fields(existing: dict, pin: dict) -> list[str]:
    """The commitments `pin` would change in `existing`, by name; empty if none."""
    return [name for field, name in PIN_COMMITMENTS if existing.get(field) != pin[field]]


def _now_utc() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_pin(args, found: Discovered) -> dict:
    """The pin artifact, exactly as it is written.

    Separated from the fetch so the fields it must carry are assertable without a
    network: a pin that omits `position_profile` or `leaf_profile` is refused when the
    verifier loads it.
    """
    return {
        "schema": SCHEMA,
        "service_identifier": args.service_identifier or args.service_uri,
        "discovery_method": args.method,
        "discovery_uri": found.uri,
        "fetched_at": _now_utc(),
        # An EMPTY kid is written only for a service whose receipts genuinely carry
        # none (`--any-single-key`), and `ScittServiceTrustPin::resolve` treats it as
        # "matches an unlabelled receipt". Writing it for any other reason would make
        # the pin match receipts it was never fetched for.
        "kid": found.kid if found.kid is not None else "",
        "algorithm": found.fields["algorithm"],
        "public_key": found.fields["public_key"],
        "public_key_thumbprint": found.fields["thumbprint"],
        "discovery_document_digest": found.document_digest,
        # Written ALWAYS: the verifier refuses a pin that omits either profile.
        "leaf_profile": args.leaf_profile,
        "position_profile": args.position_profile,
    }
