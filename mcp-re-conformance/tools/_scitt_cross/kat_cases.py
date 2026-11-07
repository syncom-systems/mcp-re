# SPDX-License-Identifier: Apache-2.0
"""The external -> us cases: what an independent implementation builds, and what MCP-RE owes each."""

from __future__ import annotations

from dataclasses import dataclass

from _scitt_cross.build import ReceiptFlaws
from _scitt_cross.constants import ALG_EDDSA, ALG_ES256, DRAFT_VDP, DRAFT_VDS


@dataclass(frozen=True)
class CaseSpec:
    name: str
    description: str
    algorithm: int
    flaws: ReceiptFlaws
    expect: str
    pin: str
    other_statement: bool = False


def case_specs(log_size: int) -> list[CaseSpec]:
    """The eight cases, in the order the corpus records them."""
    plain = ReceiptFlaws()
    return [
        CaseSpec(
            "x01_external_eddsa_receipt",
            "An EdDSA Receipt of Inclusion built by an independent implementation from "
            "RFC 9942 §5.2.1. MCP-RE must accept it.",
            ALG_EDDSA, plain, "verify_ok", "ed",
        ),
        CaseSpec(
            "x02_external_es256_receipt",
            "The same receipt signed with ES256 (RFC 6979 deterministic), which is what "
            "a real transparency service signs with. MCP-RE must accept it.",
            ALG_ES256, plain, "verify_ok", "es",
        ),
        CaseSpec(
            "x03_draft_era_labels_refused",
            "A receipt using the pre-publication draft labels -111/-222 instead of "
            "vds=395/vdp=396. This is the exact defect that shipped; MCP-RE must refuse it, "
            "so a regression to those labels fails here.",
            ALG_EDDSA, ReceiptFlaws(vds_label=DRAFT_VDS, vdp_label=DRAFT_VDP),
            "verify_fail", "ed",
        ),
        CaseSpec(
            "x04_unsupported_vds_refused",
            "A vds naming a structure MCP-RE does not implement. It must be refused, never "
            "walked as if it were RFC9162_SHA256.",
            ALG_EDDSA, ReceiptFlaws(vds_value=99), "verify_fail", "ed",
        ),
        CaseSpec(
            "x05_forged_inclusion_path_refused",
            "A sibling hash altered in the unprotected path. The service signature stays "
            "valid, so only re-deriving the root refuses it.",
            ALG_EDDSA, ReceiptFlaws(corrupt_path=True), "verify_fail", "ed",
        ),
        CaseSpec(
            "x06_leaf_index_outside_tree_refused",
            "leaf-index == tree-size. RFC 9942 §5.2 requires failing the proof; the tree-head "
            "signature is untouched.",
            ALG_EDDSA, ReceiptFlaws(override_leaf_index=log_size), "verify_fail", "ed",
        ),
        CaseSpec(
            "x07_der_es256_signature_refused",
            "An ES256 signature in ASN.1/DER instead of RFC 9053 §2.1 fixed-width r||s. The "
            "same signature mathematically, a different byte string; it must be refused.",
            ALG_ES256, ReceiptFlaws(der_signature=True), "verify_fail", "es",
        ),
        CaseSpec(
            "x08_receipt_for_another_statement_refused",
            "A genuine receipt for a different statement in the same log. Both signatures "
            "verify; the proof does not re-derive the root from THIS statement's leaf.",
            ALG_EDDSA, plain, "verify_fail", "ed", other_statement=True,
        ),
    ]
