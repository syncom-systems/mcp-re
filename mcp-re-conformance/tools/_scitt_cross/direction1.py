# SPDX-License-Identifier: Apache-2.0
"""Direction 1 — our committed vectors, read by third-party code."""

from __future__ import annotations

import json
from typing import NamedTuple

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from _scitt_cross.codec import b64u_decode, sig_structure
from _scitt_cross.constants import (
    CORPUS, CWT_CLAIMS, CWT_ISS, CWT_SUB, DRAFT_VDP, DRAFT_VDS, INCLUSION_PROOF,
    RFC9162_SHA256, VDP, VDS,
)
from _scitt_cross.fold import fold_rfc9162


class ReceiptView(NamedTuple):
    """What the independent reader found in one receipt."""

    cose: object
    vds_ok: bool
    vdp_ok: bool
    tree_size: int | None
    leaf_index: int | None
    proof_path: list

    @property
    def readable(self) -> bool:
        return self.vds_ok and self.vdp_ok


def verify_sign1_ed25519(cose: bytes, pubkey: bytes) -> bool:
    tag = cbor2.loads(cose)
    assert tag.tag == 18, f"expected COSE_Sign1 tag 18, got {tag.tag}"
    protected, _unprotected, payload, signature = tag.value
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(
            signature, sig_structure(protected, payload)
        )
        return True
    except InvalidSignature:
        return False


def _report_statement(statement: bytes) -> bool:
    st = cbor2.loads(statement)
    claims = cbor2.loads(st.value[0]).get(CWT_CLAIMS, {})
    ok = st.tag == 18 and CWT_ISS in claims and CWT_SUB in claims
    print(f"  statement  tag18={st.tag == 18}  CWT_Claims(15) iss={claims.get(CWT_ISS)!r} "
          f"sub={claims.get(CWT_SUB)!r}  -> RFC 9943 §6.1: {ok}")
    return ok


def _report_receipt(receipt: bytes) -> ReceiptView:
    rc = cbor2.loads(receipt)
    rprot = cbor2.loads(rc.value[0])
    runprot = rc.value[1]
    vdp = runprot.get(VDP)
    # cbor2 decodes CBOR maps to frozendict, which is not a dict subclass.
    vdp_ok = hasattr(vdp, "keys") and INCLUSION_PROOF in vdp
    tree_size = leaf_index = None
    proof_path: list = []
    if vdp_ok:
        tree_size, leaf_index, proof_path = cbor2.loads(vdp[INCLUSION_PROOF][0])
    print(f"  receipt    vds(395)={rprot.get(VDS)}  vdp(396) map with -1: {vdp_ok}  "
          f"tree_size={tree_size} leaf_index={leaf_index} path_len={len(proof_path)}")
    print(f"             draft labels absent: "
          f"{DRAFT_VDS not in rprot and DRAFT_VDP not in runprot}   "
          f"path non-empty ([ + bstr ]): {len(proof_path) > 0}")
    return ReceiptView(rc, rprot.get(VDS) == RFC9162_SHA256, vdp_ok, tree_size, leaf_index,
                       proof_path)


def _inclusion_re_derives_root(statement: bytes, view: ReceiptView) -> bool:
    try:
        derived = fold_rfc9162(statement, view.tree_size, view.leaf_index, view.proof_path)
    except ValueError as exc:
        print(f"             fold refused: {exc}")
        return False
    return derived == view.cose.value[2]


def _crypto_verdict(vector: dict, statement: bytes, receipt: bytes, view: ReceiptView) -> str:
    issuer_ok = verify_sign1_ed25519(statement, b64u_decode(vector["issuer_pubkey_b64url"]))
    ts_ok = verify_sign1_ed25519(receipt, b64u_decode(vector["ts_pubkey_b64url"]))
    inclusion_ok = _inclusion_re_derives_root(statement, view)
    print(f"  crypto     issuer sig={issuer_ok}  ts sig={ts_ok}  "
          f"inclusion re-derives root={inclusion_ok}")
    return "verify_ok" if (issuer_ok and ts_ok and inclusion_ok) else "verify_fail"


def _unreadable_mismatch(vector: dict) -> str | None:
    # A structure this verifier cannot read is a REFUSAL, not an inconclusive
    # result: an unknown vds means the proof format is undefined here.
    agree = vector["expect"] != "verify_ok"
    print(f"  ==> independent verdict: reject (unreadable structure)  "
          f"({'AGREES' if agree else 'DISAGREES'})")
    return None if agree else f"{vector['name']}: expected to verify, structure unreadable"


def _verdict_mismatch(vector: dict, verdict: str) -> str | None:
    # The negatives carry mcp-re wire codes; an independent verifier owes only the
    # accept/reject decision, not our error taxonomy.
    agree = (verdict == "verify_ok") == (vector["expect"] == "verify_ok")
    print(f"  ==> independent verdict: {verdict}  ({'AGREES' if agree else 'DISAGREES'})")
    return None if agree else f"{vector['name']}: verdict"


def check_vector(vector: dict) -> str | None:
    """Print the independent reading of one vector; the mismatch, if it disagrees."""
    statement = b64u_decode(vector["statement_cose_b64url"])
    receipt = b64u_decode(vector["receipt_cose_b64url"])
    print(f"\n=== {vector['name']}   (vector expects: {vector['expect']}) ===")
    statement_ok = _report_statement(statement)
    view = _report_receipt(receipt)
    if not (statement_ok and view.readable):
        return _unreadable_mismatch(vector)
    return _verdict_mismatch(vector, _crypto_verdict(vector, statement, receipt, view))


def cross_verify() -> int:
    failures = []
    for path in sorted(CORPUS.glob("s0*.json")):
        with open(path, encoding="utf-8") as handle:
            mismatch = check_vector(json.load(handle))
        if mismatch:
            failures.append(mismatch)
    print("\n" + "=" * 60)
    if failures:
        print(f"MISMATCHES: {failures}")
        return 1
    print("ALL COMMITTED VECTORS AGREE (ours -> external)")
    return 0
