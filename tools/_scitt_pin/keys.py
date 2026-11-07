# SPDX-License-Identifier: Apache-2.0
"""Reading a service's public key out of COSE_Key, JWK and DID-document material.

Each reader normalises one key into the pin's fields and refuses anything the Rust verifier
does not implement: ES256 over P-256 and EdDSA over Ed25519.
"""

from __future__ import annotations

import base64
import hashlib
import json

# COSE_Key parameters (RFC 9052 §7) and algorithms (RFC 9053).
KTY, KID, ALG, CRV, X, Y = 1, 2, 3, -1, -2, -3
KTY_EC2, KTY_OKP = 2, 1
ALG_ES256, ALG_EDDSA = -7, -8
CRV_P256, CRV_ED25519 = 1, 6

COORDINATE_OCTETS = 32


def cbor2():
    """The cbor2 module, imported on demand.

    Only key normalisation needs it. Importing it at module scope made `--selftest`
    — the only proof that the https-only guard below still holds — unrunnable on a
    machine without the dependency, which is every machine the structural gates run
    on. A guard whose test cannot execute is a guard nobody is checking.
    """
    try:
        import cbor2
    except ModuleNotFoundError:
        raise SystemExit(
            "this path needs the cbor2 package: pip install cbor2"
        ) from None
    return cbor2


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cose_key_thumbprint(kty: int, crv: int, x: bytes, y: bytes | None) -> str:
    """RFC 9679 COSE Key Thumbprint: SHA-256 over the canonical required-parameter map.

    Only the parameters that identify the key go in — not `kid`, not `alg`. A thumbprint
    that included the label would change when a service relabelled the same key, which
    would defeat comparing "is this the key I saw before" across a corpus.
    """
    required = {KTY: kty, CRV: crv, X: x}
    if y is not None:
        required[Y] = y
    canonical = cbor2().dumps(dict(sorted(required.items())), canonical=True)
    return b64u(hashlib.sha256(canonical).digest())


def _es256_fields(x: bytes, y: bytes) -> dict:
    return {
        "algorithm": "ES256",
        "public_key": {"x": b64u(x), "y": b64u(y)},
        "thumbprint": cose_key_thumbprint(KTY_EC2, CRV_P256, x, y),
    }


def _eddsa_fields(x: bytes) -> dict:
    return {
        "algorithm": "EdDSA",
        "public_key": {"x": b64u(x)},
        "thumbprint": cose_key_thumbprint(KTY_OKP, CRV_ED25519, x, None),
    }


def _cose_es256(entry: dict) -> dict:
    x, y = entry.get(X), entry.get(Y)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise SystemExit("EC2 P-256 key is missing bytes-valued x/y")
    if len(x) != COORDINATE_OCTETS or len(y) != COORDINATE_OCTETS:
        raise SystemExit(f"EC2 P-256 coordinates must be 32 octets, got {len(x)}/{len(y)}")
    return _es256_fields(x, y)


def _cose_eddsa(entry: dict) -> dict:
    x = entry.get(X)
    if not isinstance(x, bytes) or len(x) != COORDINATE_OCTETS:
        raise SystemExit("OKP Ed25519 key must carry a 32-octet x")
    return _eddsa_fields(x)


def key_from_cose(entry: dict) -> dict:
    """Normalize one COSE_Key into pin fields, refusing anything unsupported."""
    kty, crv = entry.get(KTY), entry.get(CRV)
    if kty == KTY_EC2 and crv == CRV_P256:
        return _cose_es256(entry)
    if kty == KTY_OKP and crv == CRV_ED25519:
        return _cose_eddsa(entry)
    raise SystemExit(
        f"unsupported COSE key (kty={kty!r} crv={crv!r}); this verifier implements "
        "ES256 over P-256 and EdDSA over Ed25519"
    )


def _jwk_es256(entry: dict) -> dict:
    x, y = b64u_decode(entry["x"]), b64u_decode(entry["y"])
    if len(x) != COORDINATE_OCTETS or len(y) != COORDINATE_OCTETS:
        raise SystemExit(f"P-256 coordinates must be 32 octets, got {len(x)}/{len(y)}")
    return _es256_fields(x, y)


def key_from_jwk(entry: dict) -> dict:
    """Normalize one JWK into pin fields."""
    kty, crv = entry.get("kty"), entry.get("crv")
    if kty == "EC" and crv == "P-256":
        return _jwk_es256(entry)
    if kty == "OKP" and crv == "Ed25519":
        return _eddsa_fields(b64u_decode(entry["x"]))
    raise SystemExit(f"unsupported JWK (kty={kty!r} crv={crv!r})")


def did_verification_keys(document: bytes) -> list:
    """The JWKs a W3C DID document's `verificationMethod` entries carry.

    Read as a KEY SET and no more. A DID document also asserts a controller, a set of
    verification RELATIONSHIPS and an identifier that a resolver is supposed to have
    dereferenced — none of which this tool establishes, and pretending otherwise would put
    an unearned claim in the pin. What comes out is "these are the public keys that
    document listed", which is exactly what the `jwks` method produces and what a pin
    records.

    A method's `id` fragment is NOT read as a `kid`. It identifies a verification method
    inside a DID document; a COSE `kid` is the label a receipt's protected header names,
    and the two are only ever equal by a service's choice. Taking the fragment would have
    written a `kid` into the pin that no receipt from this service carries — and the pin's
    `kid` field means "the one the receipt names". A JWK that carries its own `kid` keeps
    it, because that one is the JOSE label and does correspond.
    """
    methods = json.loads(document).get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise SystemExit("the DID document has no verificationMethod entries")
    # Multibase and PEM forms are legal DID material and are not JWKs. Refusing to guess
    # is the point: a key this tool cannot read must not become a pin.
    keys = [dict(m["publicKeyJwk"]) for m in methods if isinstance(m.get("publicKeyJwk"), dict)]
    if not keys:
        raise SystemExit(
            "the DID document lists no verificationMethod carrying a publicKeyJwk; this "
            "tool reads JWK material only"
        )
    return keys


def _select_by_kid(entries: list, kid: str, kid_of) -> tuple:
    matches = [e for e in entries if kid_of(e) == kid]
    if not matches:
        available = sorted(str(kid_of(e)) for e in entries)
        raise SystemExit(f"no key with kid {kid!r}; the service advertises {available}")
    if len(matches) > 1:
        raise SystemExit(f"{len(matches)} keys share kid {kid!r}; refusing to guess")
    return matches[0], kid


def select(entries: list, kid: str | None, any_single: bool, kid_of) -> tuple:
    """Pick the entry the receipt names, or the only one if that is what was asked for."""
    if kid is not None:
        return _select_by_kid(entries, kid, kid_of)
    if not any_single:
        raise SystemExit("pass --kid, or --any-single-key if the set holds exactly one key")
    if len(entries) != 1:
        raise SystemExit(f"--any-single-key needs exactly one key, the set has {len(entries)}")
    return entries[0], kid_of(entries[0])
