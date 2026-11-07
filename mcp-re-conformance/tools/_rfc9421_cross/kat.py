# SPDX-License-Identifier: Apache-2.0
"""external → us: a signature `cryptography` produced, for the Rust verifier to accept."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _rfc9421_cross.b64 import b64url_nopad


def emit_external_kat(corpus: Path) -> None:
    """external → us: sign a fixed base with `cryptography` and commit it so the
    Rust verifier can confirm it accepts an externally-produced signature."""
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    base = (
        '"@method": POST\n'
        '"content-type": application/json\n'
        '"@signature-params": ("@method" "content-type");created=1700000000;'
        'keyid="ext-key";alg="ed25519";tag="mcp-re-http-v1"'
    ).encode()
    out = {
        "note": "Signature produced by python-cryptography (independent of ed25519-dalek).",
        "seed_b64url": b64url_nopad(seed),
        "public_key_b64url": b64url_nopad(sk.public_key().public_bytes_raw()),
        "signature_base_b64url": b64url_nopad(base),
        "signature_b64url": b64url_nopad(sk.sign(base)),
    }
    (corpus / "external_kat.json").write_text(json.dumps(out, indent=2) + "\n")
    print("emitted external_kat.json")
