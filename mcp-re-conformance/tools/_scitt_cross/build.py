# SPDX-License-Identifier: Apache-2.0
"""Direction 2 builders — Signed Statements and Receipts of Inclusion made here, not by MCP-RE."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from _scitt_cross.codec import sig_structure
from _scitt_cross.constants import (
    ALG_EDDSA, CWT_CLAIMS, CWT_IAT, CWT_ISS, CWT_SUB, HDR_ALG, HDR_CTY, HDR_KID,
    INCLUSION_PROOF, ISSUED_AT, ISSUER_KID, ISSUER_SEED, RFC9162_SHA256, STATEMENT_CTY,
    STATEMENT_SUBJECT, TS_EC_SCALAR, TS_ED_SEED, TS_KID, VDP, VDS,
)


@dataclass(frozen=True)
class ReceiptFlaws:
    """The deliberate departures from RFC 9942 a refusal case builds in."""

    vds_label: int = VDS
    vdp_label: int = VDP
    vds_value: int = RFC9162_SHA256
    override_leaf_index: int | None = None
    corrupt_path: bool = False
    der_signature: bool = False


def build_statement(commitment: dict) -> bytes:
    """An RFC 9943 §6.1 Signed Statement, built here rather than by MCP-RE."""
    payload = cbor2.dumps(commitment, canonical=True)
    protected = cbor2.dumps(
        {
            HDR_ALG: ALG_EDDSA,
            HDR_CTY: STATEMENT_CTY,
            HDR_KID: ISSUER_KID.encode(),
            CWT_CLAIMS: {CWT_ISS: ISSUER_KID, CWT_SUB: STATEMENT_SUBJECT, CWT_IAT: ISSUED_AT},
        },
        canonical=True,
    )
    signature = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(
        sig_structure(protected, payload)
    )
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def _mth(nodes: list[bytes], want: int | None) -> tuple[bytes, list[bytes]]:
    """RFC 9162 §2.1.1 MTH over `nodes`, and the §2.1.3.1 path for leaf `want` (if any)."""
    if not nodes:
        return hashlib.sha256(b"").digest(), []
    if len(nodes) == 1:
        return nodes[0], []
    k = 1 << (len(nodes) - 1).bit_length() - 1
    left_nodes, right_nodes = nodes[:k], nodes[k:]
    if want is None:
        left, _ = _mth(left_nodes, None)
        right, _ = _mth(right_nodes, None)
        return hashlib.sha256(b"\x01" + left + right).digest(), []
    if want < k:
        left, path = _mth(left_nodes, want)
        right, _ = _mth(right_nodes, None)
        path = path + [right]
    else:
        left, _ = _mth(left_nodes, None)
        right, path = _mth(right_nodes, want - k)
        path = path + [left]
    return hashlib.sha256(b"\x01" + left + right).digest(), path


def merkle(leaves: list[bytes], target: int) -> tuple[bytes, list[bytes]]:
    """RFC 9162 §2.1.1 MTH and §2.1.3.1 PATH for `target`.

    The split is at the largest power of two STRICTLY below n, and the last node is
    never duplicated. Those are different trees for every size that is not a power of
    two, and the two corpora were both recorded at tree_size = 2 — the one size where
    they coincide, which is why a duplicate-last-node implementation on both sides of
    the cross-check went unnoticed.
    """
    return _mth([hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves], target)


def _flip_last_bit_of_first(path: list[bytes]) -> list[bytes]:
    tampered = bytearray(path[0])
    tampered[-1] ^= 0x01
    return [bytes(tampered)] + path[1:]


def _es256_signature(signed: bytes, der: bool) -> bytes:
    key = ec.derive_private_key(TS_EC_SCALAR, ec.SECP256R1())
    # RFC 6979 deterministic ECDSA. Randomized signing would make the emitted KAT
    # differ on every run, and the drift guard (`git diff --exit-code`) would fail
    # forever — a gate that cannot be satisfied gets disabled, not fixed.
    encoded = key.sign(signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if der:
        # RFC 9053 §2.1 requires fixed-width r||s; DER must be refused.
        return encoded
    r, s = decode_dss_signature(encoded)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _service_signature(algorithm: int, signed: bytes, der: bool) -> bytes:
    if algorithm == ALG_EDDSA:
        return Ed25519PrivateKey.from_private_bytes(TS_ED_SEED).sign(signed)
    return _es256_signature(signed, der)


def build_receipt(
    statements: list[bytes],
    target: int,
    algorithm: int,
    flaws: ReceiptFlaws = ReceiptFlaws(),
) -> bytes:
    """An RFC 9942 §5.2.1 Receipt of Inclusion, built independently of MCP-RE."""
    root, path = merkle(statements, target)
    if flaws.corrupt_path and path:
        path = _flip_last_bit_of_first(path)
    leaf_index = target if flaws.override_leaf_index is None else flaws.override_leaf_index
    proof = cbor2.dumps([len(statements), leaf_index, path])
    protected = cbor2.dumps(
        {HDR_ALG: algorithm, HDR_KID: TS_KID.encode(), flaws.vds_label: flaws.vds_value},
        canonical=True,
    )
    unprotected = {flaws.vdp_label: {INCLUSION_PROOF: [proof]}}
    signature = _service_signature(algorithm, sig_structure(protected, root), flaws.der_signature)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, root, signature]))
