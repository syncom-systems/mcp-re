# SPDX-License-Identifier: Apache-2.0
"""Direction 2 — artifacts this script builds, which MCP-RE must accept or refuse."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _scitt_cross.build import build_receipt, build_statement
from _scitt_cross.codec import b64u
from _scitt_cross.constants import EXTERNAL_KAT, ISSUER_SEED, TS_EC_SCALAR, TS_ED_SEED, TS_KID
from _scitt_cross.kat_cases import CaseSpec, case_specs

# No `submitted_commitment`: an independent implementation issues under the profile
# it implements, not under MCP-RE's. The vector is the check that such a statement
# still parses and verifies rather than being refused for a field it never carried.
COMMITMENT = {
    "request_evidence": "external-request-handle",
    "response_evidence": "external-response-handle",
    "chain_label": "complete",
    "chain_commitment": "external-chain-commitment",
}


def trust_pins() -> dict:
    """The service trust pins the cases verify under, by the key the case names."""
    ec_point = (
        ec.derive_private_key(TS_EC_SCALAR, ec.SECP256R1()).public_key().public_numbers()
    )
    ed_ts_public = (
        Ed25519PrivateKey.from_private_bytes(TS_ED_SEED).public_key().public_bytes_raw()
    )
    ed_pin = {
        "schema": "mcp-re-scitt-service-trust-pin/v1",
        "service_identifier": "external-cross-verify",
        "discovery_method": "well-known-scitt-keys",
        "discovery_uri": "https://external.invalid/.well-known/scitt-keys",
        "fetched_at": "2026-07-31T00:00:00Z",
        "kid": TS_KID,
        "algorithm": "EdDSA",
        "public_key": {"x": b64u(ed_ts_public)},
        "public_key_thumbprint": b64u(hashlib.sha256(ed_ts_public).digest()),
        "discovery_document_digest": b64u(hashlib.sha256(b"external-discovery").digest()),
        # Both profiles are written: a pin that omits either is refused. These receipts
        # carry no position commitment and log the statement's own octets.
        "leaf_profile": "statement-bytes",
        "position_profile": "unbound",
    }
    es_pin = {
        **ed_pin,
        "algorithm": "ES256",
        "public_key": {
            "x": b64u(ec_point.x.to_bytes(32, "big")),
            "y": b64u(ec_point.y.to_bytes(32, "big")),
        },
    }
    return {"ed": ed_pin, "es": es_pin}


def _issuer_public() -> str:
    return b64u(Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).public_key().public_bytes_raw())


def _case_document(spec: CaseSpec, log: list[bytes], statements: dict, pins: dict) -> dict:
    # Two leaves, so the inclusion path is non-empty as `[ + bstr ]` requires.
    receipt = build_receipt(log, len(log) - 1, spec.algorithm, spec.flaws)
    chosen = statements["other" if spec.other_statement else "statement"]
    return {
        "name": spec.name,
        "description": spec.description,
        "statement_cose_b64url": b64u(chosen),
        "receipt_cose_b64url": b64u(receipt),
        "issuer_pubkey_b64url": _issuer_public(),
        "ts_trust_pin": pins[spec.pin],
        "expect": spec.expect,
    }


def build_cases() -> list[dict]:
    statement = build_statement(COMMITMENT)
    other = build_statement({**COMMITMENT, "chain_label": "incomplete:1:MissingContinuation"})
    log = [other, statement]
    statements = {"statement": statement, "other": other}
    pins = trust_pins()
    return [_case_document(spec, log, statements, pins) for spec in case_specs(len(log))]


def emit_external_kat() -> int:
    cases = build_cases()
    document = {
        "schema": "mcp-re-scitt-external-kat/v1",
        "produced_by": "mcp-re-conformance/tools/scitt_cross_verify.py (cbor2 + cryptography)",
        "profiles": ["RFC 9943 §6.1", "RFC 9942 §5.2.1", "RFC 9162", "RFC 9052 §4.4"],
        "cases": cases,
    }
    with open(EXTERNAL_KAT, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {len(cases)} externally built cases to {EXTERNAL_KAT}")
    print("  positives:", ", ".join(c["name"] for c in cases if c["expect"] == "verify_ok"))
    print("  refusals: ", ", ".join(c["name"] for c in cases if c["expect"] != "verify_ok"))
    return 0
