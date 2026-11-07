// SPDX-License-Identifier: Apache-2.0
//! The nine vectors, one function each, built from the fixed keys and statements.

use mcp_re_core::b64url_encode;
use mcp_re_http_profile::chain::ChainLabel;
use mcp_re_http_profile::chain::IncompleteReason;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::SignedStatement;

use super::bytes::find;
use super::bytes::find_once;
use super::bytes::splice;
use super::bytes::PROOF_HEAD;
use super::bytes::VDS_ENTRY;
use super::manifest::Case;
use super::manifest::Fixture;
use super::material::commitment;
use super::material::log_with_fillers;
use super::material::register;
use super::material::register_in;
use super::material::statement;
use super::material::statement_by;
use super::material::stranger;

/// The two registered statements most vectors start from.
struct Base {
    complete: SignedStatement,
    receipt: Receipt,
    incomplete: SignedStatement,
    incomplete_receipt: Receipt,
}

impl Base {
    fn new() -> Self {
        let complete = statement(commitment(ChainLabel::Complete, 2));
        let receipt = register(&complete);
        let incomplete = statement(commitment(
            ChainLabel::Incomplete {
                hop: 1,
                reason: IncompleteReason::MissingContinuation,
            },
            2,
        ));
        let incomplete_receipt = register(&incomplete);
        Self {
            complete,
            receipt,
            incomplete,
            incomplete_receipt,
        }
    }
}

pub(super) fn build_fixtures() -> Vec<Fixture> {
    let base = Base::new();
    vec![
        s01_complete_record(&base),
        s02_incomplete_record(&base),
        s03_tampered_payload(&base),
        s04_receipt_for_another_statement(&base),
        s05_untrusted_issuer(),
        s06_forged_inclusion_path(&base),
        s07_unsupported_vds(&base),
        s08_leaf_index_outside_tree(&base),
        s09_right_edge_leaf_of_a_three_leaf_log(),
    ]
}

/// s01 — a complete call record: the positive.
fn s01_complete_record(base: &Base) -> Fixture {
    Case {
        name: "s01_complete_record",
        description: "A two-hop COMPLETE call record, registered and offline-verifiable: issuer \
         COSE_Sign1 signature, RFC 9162 inclusion proof, and the service's signature \
         over the root the proof re-derives.",
        expect: "verify_ok",
    }
    .pin(&base.complete, &base.receipt)
}

/// s02 — an INCOMPLETE record. It verifies exactly as well as a complete one, and
/// says so: a receipt can never make a truncated call look whole, because the
/// label it commits to names the failing hop.
fn s02_incomplete_record(base: &Base) -> Fixture {
    Case {
        name: "s02_incomplete_record",
        description: "An INCOMPLETE record verifies as a receipt and remains labelled incomplete. \
         A valid receipt over a truncated chain is a correct record OF a truncated \
         chain, not evidence the call was whole.",
        expect: "verify_ok",
    }
    .pin(&base.incomplete, &base.incomplete_receipt)
}

/// s03 — the payload tampered in the COSE bytes, same length so the CBOR still
/// parses and the failure is the SIGNATURE rather than a decode error.
fn s03_tampered_payload(base: &Base) -> Fixture {
    let mut tampered = base.complete.to_cose().to_vec();
    let at = find(&tampered, b"complete").expect("the label is in the payload");
    tampered[at..at + 8].copy_from_slice(b"complet3");
    Fixture {
        statement_cose_b64url: b64url_encode(&tampered),
        ..Case {
            name: "s03_tampered_payload",
            description: "The committed chain label rewritten in the signed payload, at \
                      the same length so the CBOR still parses. The refusal must be \
                      the signature's, not the decoder's.",
            expect: "mcp-re.invalid_signature",
        }
        .pin(&base.complete, &base.receipt)
    }
}

/// s04 — a receipt that is genuine, for a DIFFERENT statement. This is the
/// substitution an attacker actually has available: both artifacts verify on
/// their own, and only the binding between them fails. A verifier that checked
/// the two signatures without re-deriving the root from THIS statement's leaf
/// would accept it.
fn s04_receipt_for_another_statement(base: &Base) -> Fixture {
    Case {
        name: "s04_receipt_for_another_statement",
        description:
            "A genuine receipt paired with a different genuine statement. Both signatures \
         verify; the inclusion proof does not re-derive the signed root from this \
         statement's leaf. Checking signatures alone would accept the swap.",
        expect: "mcp-re.request_binding_mismatch",
    }
    .pin(&base.complete, &base.incomplete_receipt)
}

/// s05 — a statement naming an issuer the verifier does not resolve. The
/// signature over it is perfectly valid; nobody trusted the signer.
fn s05_untrusted_issuer() -> Fixture {
    let foreign = statement_by(
        "scitt-issuer-rogue",
        commitment(ChainLabel::Complete, 1),
        &stranger(),
    );
    let foreign_receipt = register(&foreign);
    Case {
        name: "s05_untrusted_issuer",
        description:
            "A statement naming an issuer the verifier does not resolve, signed by a REAL \
         Ed25519 key. The signature is valid; nobody trusted the signer. A kid never \
         introduces trust.",
        expect: "mcp-re.actor_binding_failed",
    }
    .pin(&foreign, &foreign_receipt)
}

/// s06 — a sibling hash altered inside the inclusion path. The path rides in the
/// UNPROTECTED header, so this tamper leaves the service's signature over the root
/// perfectly valid: the ONLY thing that catches it is re-deriving the root from
/// this statement's leaf. A verifier that trusted a valid receipt signature and
/// skipped the fold would accept a forged path.
fn s06_forged_inclusion_path(base: &Base) -> Fixture {
    let at = find_once(base.receipt.to_cose(), &PROOF_HEAD) + PROOF_HEAD.len();
    let mut forged_path = base.receipt.to_cose().to_vec();
    forged_path[at + 31] ^= 0x01;
    Fixture {
        receipt_cose_b64url: b64url_encode(&forged_path),
        ..Case {
            name: "s06_forged_inclusion_path",
            description: "One sibling hash flipped inside the inclusion path. The proof is \
                      unprotected, so the service's signature over the root still \
                      verifies; only re-deriving the root from this leaf refuses it.",
            expect: "mcp-re.request_binding_mismatch",
        }
        .pin(&base.complete, &base.receipt)
    }
}

/// s07 — a verifiable data structure this verifier does not implement. RFC 9942
/// registers only RFC9162_SHA256 (1); anything else names a proof format whose
/// walk is undefined here. The refusal must come from the structure check, BEFORE
/// any signature is verified — walking an unknown proof format and only then asking
/// about signatures would be the wrong order.
fn s07_unsupported_vds(base: &Base) -> Fixture {
    let patched = splice(
        base.receipt.to_cose(),
        &VDS_ENTRY,
        &[0x19, 0x01, 0x8b, 0x02],
    );
    Fixture {
        receipt_cose_b64url: b64url_encode(&patched),
        ..Case {
            name: "s07_unsupported_vds",
            description: "The vds in the protected header names a structure this verifier \
                      does not implement. It must be refused for that reason, at parse, \
                      before any signature is checked — never walked as if it were \
                      RFC9162_SHA256.",
            expect: "mcp-re.malformed_envelope",
        }
        .pin(&base.complete, &base.receipt)
    }
}

/// s08 — a leaf index at the tree size. RFC 9942 §5.2, quoting RFC 9162: fail the
/// proof. The index is in the unprotected proof, so the tree-head signature stays
/// valid; a tree of size 2 simply has no leaf 2, and arithmetic settles it before
/// any hashing.
fn s08_leaf_index_outside_tree(base: &Base) -> Fixture {
    let patched = splice(
        base.receipt.to_cose(),
        &PROOF_HEAD,
        &[0x83, 0x02, 0x02, 0x81, 0x58, 0x20],
    );
    Fixture {
        receipt_cose_b64url: b64url_encode(&patched),
        ..Case {
            name: "s08_leaf_index_outside_tree",
            description: "leaf-index equal to tree-size. RFC 9942 §5.2 requires failing \
                      such a proof; the signature over the tree head is untouched and \
                      still valid, so only the bounds check refuses it.",
            expect: "mcp-re.malformed_envelope",
        }
        .pin(&base.complete, &base.receipt)
    }
}

/// s09 — a THREE-leaf log, target on the short right edge. The one shape that
/// separates RFC 9162 from the duplicate-last-node tree: for every power-of-two
/// size the two constructions agree, and both this corpus and both interop corpora
/// were recorded at size 2, so the divergence was invisible everywhere. Leaf 2 of a
/// 3-leaf tree is promoted past a level rather than paired, which an index-bit fold
/// gets wrong in the operand order — so this vector fails on any verifier that is
/// not running §2.1.3.2's fn/sn walk.
fn s09_right_edge_leaf_of_a_three_leaf_log() -> Fixture {
    let target = statement(commitment(ChainLabel::Complete, 3));
    let receipt = register_in(&mut log_with_fillers(2), &target);
    assert_eq!(receipt.tree_size(), 3, "a non-power-of-two log");
    assert_eq!(receipt.leaf_index(), 2, "the right-edge leaf");
    Case {
        name: "s09_right_edge_leaf_of_a_three_leaf_log",
        description: "Leaf 2 of a THREE-leaf log — the right-edge promotion case of RFC 9162          §2.1.3.2. Every power-of-two tree size hides the difference between the RFC          tree and a duplicate-last-node one; this is the smallest size that does not.",
        expect: "verify_ok",
    }
    .pin(&target, &receipt)
}
