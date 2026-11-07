# SPDX-License-Identifier: Apache-2.0
"""Verifying the committed http-profile fixtures with an independent Ed25519 implementation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from _rfc9421_cross.b64 import b64url_nopad
from _rfc9421_cross.kat import emit_external_kat
from _rfc9421_cross.messages import header
from _rfc9421_cross.signature_input import (
    dictionary_member, keyid_and_tag, parse_signature_input, reconstruct_base, signature_bytes,
)

# TEST-ONLY key seeds, identical to the Rust corpus writer
# (CLIENT_SEED = [11u8; 32], SERVER_SEED = [22u8; 32]).
CLIENT_SEED = bytes([11]) * 32
SERVER_SEED = bytes([22]) * 32

KEYS: dict[str, Ed25519PublicKey] = {
    "client-key-1": Ed25519PrivateKey.from_private_bytes(CLIENT_SEED).public_key(),
    "server-key-1": Ed25519PrivateKey.from_private_bytes(SERVER_SEED).public_key(),
}

PROFILE_TAG = "mcp-re-http-v1"

POSITIVE = {
    "h01_request_valid",
    "h07_response_valid",
    "h18_rejection_bound_valid",
    "h19_rejection_unbound_valid",
}


class GateFailure(Exception):
    """A mismatch that fails the gate, carrying the line the gate prints."""


def verify_fixture(fx: dict) -> bytes:
    kind = fx["kind"]
    label = "mcp-re" if kind == "request" else "mcp-re-response"
    request = fx.get("request")
    response = fx.get("response")
    msg_headers = (request if kind == "request" else response)["headers"]
    si = dictionary_member(header(msg_headers, "signature-input"), label)
    comps, params = parse_signature_input(si)
    keyid, tag = keyid_and_tag(params)
    if tag != PROFILE_TAG:
        raise ValueError(f"foreign tag {tag}")
    base = reconstruct_base(comps, si, request, response if kind != "request" else None)
    KEYS[keyid].verify(signature_bytes(msg_headers, label), base)
    return base


def _read_pinned(corpus: Path, entry: dict) -> bytes:
    # Manifest entries are content-pinned (#415 rev 2 §12.2, MCPRE-427): each is
    # {file, sha256}. As the third-party verifier, check the pin before reading —
    # the whole point of §12.2 is that a reviewer proves it read the same bytes.
    name = entry["file"]
    raw = (corpus / name).read_bytes()
    want_hash = entry["sha256"]
    got_hash = hashlib.sha256(raw).hexdigest()
    if got_hash != want_hash:
        raise GateFailure(f"FAIL {name}: manifest sha256 mismatch\n  file={got_hash}\n  manifest={want_hash}")
    return raw


def _check_oracle(fx: dict, base: bytes) -> None:
    """Byte-compare h01's reconstructed base against the frozen oracle."""
    if not fx.get("oracle"):
        return
    want = fx["oracle"]["signature_base_b64url"]
    got = b64url_nopad(base)
    if got != want:
        raise GateFailure(f"FAIL {fx['name']}: base mismatch\n  ext={got}\n  oracle={want}")


def _verify_entry(corpus: Path, entry: dict) -> bool:
    """True when the entry was a positive fixture and verified."""
    fx = json.loads(_read_pinned(corpus, entry))
    # The manifest also pins the external KAT (a third-party artifact with no
    # Fixture `name`); its hash is checked above, and it is replayed by its own
    # harness, not this positive-fixture loop.
    if fx.get("name") not in POSITIVE:
        return False
    _check_oracle(fx, verify_fixture(fx))
    print(f"ok  external-verify {fx['name']}")
    return True


def _verify_corpus(corpus: Path) -> int:
    manifest = json.loads((corpus / "manifest.json").read_text())
    checked = sum(_verify_entry(corpus, entry) for entry in manifest["fixtures"])
    if checked == 0:
        raise GateFailure("FAIL: no positive fixtures verified")
    return checked


def run(argv: list[str], default_corpus: Path) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    corpus = Path(args[0]) if args else default_corpus
    try:
        checked = _verify_corpus(corpus)
    except GateFailure as failure:
        print(failure)
        return 1
    if "--emit-external-kat" in flags:
        emit_external_kat(corpus)
    print(f"PASS: {checked} MCP-RE http-profile signatures verified by an independent RFC 9421 impl")
    return 0
