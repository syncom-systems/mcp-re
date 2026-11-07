// SPDX-License-Identifier: Apache-2.0
//! MCPRE-501 slice 4 — offline verification of a receipt produced by a THIRD-PARTY
//! implementation of RFC 9942.
//!
//! The peer is `@transmute/cose` 0.3.0 (npm), authored by the RFC 9942 editor. Its
//! RFC 9162 `Tree`, its `encode_inclusion_proof`, and its CBOR encoder built the
//! receipt in `tests/vectors/scitt/interop/`; the Ed25519 signature came from Node's
//! `crypto`. No MCP-RE code produced any of it. The statement it commits to is our own
//! frozen `s01` statement, byte-for-byte.
//!
//! **What this establishes.** MCP-RE Signed Statements are read by an independent SCITT
//! implementation, and a receipt that implementation produces verifies offline under the
//! MCP-RE verifier against a pinned service key, retained evidence, and an RFC 9942
//! inclusion proof.
//!
//! A second peer is a real SCITT Transparency SERVICE: `capsule-anchor`
//! (action-state-group, Apache-2.0), run locally, which accepted our exact statement over
//! HTTP and returned a detached-payload receipt. Its corpus is in `interop/capsule-anchor/`.
//! The two peers disagree about the Merkle LEAF PREIMAGE — `@transmute/cose` hashes the
//! statement's octets, `capsule-anchor` hashes a digest of them — which is why the leaf
//! profile is a qualifier on the pinned service artifact rather than a constant.
//!
//! **What neither establishes, stated so the corpus cannot be read as more than it is.**
//! `@transmute/cose` is a LIBRARY: no registration, no HTTP, no log operated by anyone.
//! `capsule-anchor` is a service, but a LOCAL run of open-source code. So neither says
//! anything about production transparency-service operation, operator independence,
//! resistance to a split-view log, witnessed transparency, or interoperability with any
//! other implementation. Each `exchange-metadata.json` records its own limits.
//!
//! The negatives are the substance. A positive alone would show only that two
//! implementations agree on a happy path; each negative mutates the third party's own
//! receipt to show MCP-RE independently enforces the contract rather than trusting it.

#[path = "scitt_interop_test/corpus.rs"]
mod corpus;
#[path = "scitt_interop_test/report.rs"]
mod report;

use corpus::{
    another_ed25519_key, artifact, capsule, interop_dir, issuer, operated_capsule, pin,
    pin_document_with, receipt, retained_chain, statement, verify_corpus, verify_with,
};
use mcp_re_core::b64url_decode;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::verify_retained_evidence;
use mcp_re_http_profile::scitt::EvidenceCommitment;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;
use report::{build_report, corpora, VerificationReport};

#[test]
fn a_third_party_receipt_verifies_offline_under_mcp_re() {
    verify_with(&statement(), &receipt(), &pin()).expect("the third party's receipt verifies");

    // Offline in the sense that matters: the producing implementation is not installed,
    // not running, and not reachable from this test. Only these bytes are.
    let r = receipt();
    assert_eq!(r.tree_size(), 2, "their tree had two leaves");
    assert_eq!(r.leaf_index(), 1, "our statement is leaf 1");
}

/// What the frozen `s01` corpus can and cannot evidence about retained evidence.
///
/// DEMOTED IN PLACE, and the demotion is the result. `s01` is a pre-revision record: its
/// statement carries no `submitted_commitment`, so it identifies no submission, and
/// `verify_retained_evidence` refuses it rather than reporting the verified-prefix match
/// as though it reached the whole record. The vector is preserved because what it does
/// establish is real — a foreign service's receipt, statement and key pin verifying
/// offline against these bytes — and because deleting a vector is how a coverage gap
/// stops being visible.
///
/// What it does NOT establish, and no assertion here may be read as establishing:
/// retained-evidence correspondence over a real call. Its `retained-evidence.bin` carries
/// the handles `req-0`/`rsp-0` rather than retained MESSAGES, so the submission digest is
/// not reproducible from it at all — the artifact cannot be made to bind a submission by
/// any change on this side. Closing that needs a regenerated corpus produced by a real
/// signed multi-hop exchange, which is a corpus-generation job and not a verifier one.
#[test]
fn the_pre_revision_corpus_cannot_bind_a_submission() {
    let statement = statement();
    let retained = retained_chain(&artifact("retained-evidence.bin"));

    assert!(
        !statement.commitment().identifies_a_submission(),
        "the frozen s01 statement is a pre-revision record"
    );
    let err = verify_retained_evidence(statement.commitment(), &retained, None, None)
        .expect_err("a statement identifying no submission cannot bind retained evidence");
    assert!(matches!(err, HttpProfileError::MalformedEvidence(_)));

    // The prefix comparison the corpus can still exercise through the public surface: the
    // chain label the issuer committed to is the one the retained artifact reproduces.
    assert_eq!(
        EvidenceCommitment::from_reconstruction(&retained, None, None).chain_label(),
        statement.commitment().chain_label(),
        "the retained artifact reproduces the committed chain label"
    );

    // The tamper and truncation controls are NOT here any more, and their absence is
    // deliberate rather than an omission. Both used to run through
    // `verify_retained_evidence`, which now refuses this corpus before reaching them, and
    // the only way to keep them here would be to widen a production projection so a test
    // could read a digest. They live with the owner instead: the retained-correspondence
    // module's own controls alter a hop, truncate the chain and substitute the unverified
    // tail, against reconstructions that carry a submission identity — which is what this
    // corpus cannot supply.
}

/// A statement identifying no submission binds no retained record — the corpus case.
///
/// The frozen `s01` statement carries no `submitted_commitment`, so it identifies no
/// submission, and the verifier refuses rather than reporting the verified-prefix match as
/// though it reached the whole record. The archivist holding the record is exactly who
/// would benefit from the weaker answer being indistinguishable from the stronger one.
///
/// The mirror control — a retained record that CLAIMS an identity the statement never made
/// — lives with the owner in `mcp-re-http-profile`, because building one means authoring a
/// submission digest, and a reconstruction cannot be given one from outside the crate that
/// computes it. That is the seal working, not a gap here.
#[test]
fn a_statement_identifying_no_submission_binds_no_retained_record() {
    let statement = statement();
    assert!(
        !statement.commitment().identifies_a_submission(),
        "the frozen s01 statement identifies no submission"
    );

    let retained = retained_chain(&artifact("retained-evidence.bin"));
    let err = verify_retained_evidence(statement.commitment(), &retained, None, None)
        .expect_err("a statement that identifies no submission cannot bind one");
    assert!(matches!(err, HttpProfileError::MalformedEvidence(_)));
}

/// A pin for a different key does not verify the receipt. The pin is what a run records;
/// pointing it at the wrong key must fail rather than fall back to anything.
#[test]
fn a_wrong_pinned_service_key_is_refused() {
    let wrong = pin_document_with(&artifact("service-key-pin.json"), |d| {
        d["public_key"]["x"] = another_ed25519_key();
    });
    assert_eq!(
        verify_with(&statement(), &receipt(), &wrong).unwrap_err(),
        HttpProfileError::ReceiptInvalid,
    );

    // And a pin whose kid does not match the receipt resolves to nothing at all.
    let other_kid = pin_document_with(&artifact("service-key-pin.json"), |d| {
        d.insert("kid".into(), "not-the-receipts-kid".into());
    });
    assert_eq!(
        verify_with(&statement(), &receipt(), &other_kid).unwrap_err(),
        HttpProfileError::ReceiptServiceUntrusted,
    );
}

/// Mutating the third party's receipt: each case breaks one property and must be
/// refused. The first three leave the service's signature VALID, because the mutated
/// fields ride in the unprotected header — so a verifier that checked signatures and
/// skipped the inclusion fold would accept them.
#[test]
fn mutations_of_the_third_party_receipt_are_refused() {
    let statement = statement();
    let bytes = artifact("receipt.cbor");

    // The CBOR of `inclusion-proof-content` for [2, 1, [32-byte sibling]].
    const PROOF_HEAD: [u8; 6] = [0x83, 0x02, 0x01, 0x81, 0x58, 0x20];
    let at = bytes
        .windows(PROOF_HEAD.len())
        .position(|w| w == PROOF_HEAD)
        .expect("their proof content is present");

    // 1. Forged inclusion path — signature over the tree head still valid.
    let mut forged = bytes.clone();
    forged[at + PROOF_HEAD.len() + 31] ^= 0x01;
    assert_eq!(
        verify_with(
            &statement,
            &Receipt::from_cose(&forged).expect("still parses"),
            &pin()
        )
        .unwrap_err(),
        HttpProfileError::ReceiptInclusionInvalid,
    );

    // 2. leaf-index == tree-size.
    let mut outside = bytes.clone();
    outside[at + 2] = 0x02;
    assert_eq!(
        Receipt::from_cose(&outside).unwrap_err(),
        HttpProfileError::MalformedEvidence("scitt inclusion proof leaf index outside tree"),
    );

    // 3. A tree size that no longer covers the proof.
    let mut resized = bytes.clone();
    resized[at + 1] = 0x01;
    assert!(
        Receipt::from_cose(&resized).is_err()
            || verify_with(
                &statement,
                &Receipt::from_cose(&resized).expect("parses"),
                &pin()
            )
            .is_err(),
        "a tree size inconsistent with the proof must not verify"
    );

    // 4. The signed payload (the Merkle root) changed — the signature must fail.
    let root_at = bytes.len() - 64 - 34;
    let mut payload = bytes.clone();
    payload[root_at] ^= 0x01;
    let outcome = Receipt::from_cose(&payload).and_then(|r| verify_with(&statement, &r, &pin()));
    assert!(outcome.is_err(), "a changed payload must not verify");
}

/// Their receipt paired with a different statement. Both artifacts are genuine; only the
/// binding between them is wrong, and only re-deriving the root from THIS statement's
/// leaf catches it.
#[test]
fn the_third_party_receipt_does_not_verify_another_statement() {
    let s02: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            interop_dir()
                .parent()
                .expect("scitt dir")
                .join("s02_incomplete_record.json"),
        )
        .expect("s02 committed"),
    )
    .expect("s02 parses");
    let other = SignedStatement::from_cose(
        &b64url_decode(s02["statement_cose_b64url"].as_str().expect("statement")).expect("b64url"),
    )
    .expect("parses");

    assert_eq!(
        verify_with(&other, &receipt(), &pin()).unwrap_err(),
        HttpProfileError::ReceiptInclusionInvalid,
    );
}

/// The corpus records what the peer was and what the exchange did NOT include, so the
/// claim cannot drift upward later.
#[test]
fn the_corpus_records_the_limits_of_the_exchange() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&artifact("manifest.json")).expect("manifest parses");
    assert_eq!(manifest["schema"], "mcp-re-scitt-interop/v1");
    assert!(
        manifest["peer"]
            .as_str()
            .expect("peer")
            .contains("@transmute/cose"),
        "the peer must be named"
    );

    let exchange: serde_json::Value =
        serde_json::from_slice(&artifact("exchange-metadata.json")).expect("metadata parses");
    assert!(
        exchange["not_a_service"]
            .as_str()
            .expect("not_a_service")
            .contains("LIBRARY"),
        "the corpus must say the peer is not a transparency service"
    );
    assert!(
        exchange["local_patch"].as_str().expect("local_patch").len() > 40,
        "the patch applied to the peer must be recorded"
    );

    // Every artifact hash in the manifest must match the bytes on disk.
    use sha2::Digest;
    for (name, expected) in manifest["artifacts"].as_object().expect("artifacts") {
        let actual = mcp_re_core::b64url_encode(&sha2::Sha256::digest(artifact(name)));
        assert_eq!(
            &actual,
            expected.as_str().expect("digest"),
            "{name} drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// capsule-anchor — a real SCITT Transparency SERVICE, run locally.
// ---------------------------------------------------------------------------

/// A real service's receipt verifies offline — detached payload, and its own leaf
/// profile taken from the pin.
#[test]
fn a_real_transparency_services_receipt_verifies_offline() {
    verify_corpus(capsule).expect("capsule-anchor's receipt verifies offline");
}

/// The qualifier decides, and exactly one value of it can be right. With the default
/// profile the same receipt does NOT verify — so the profile is doing real work, and
/// nothing silently falls back to trying the other one.
#[test]
fn the_wrong_leaf_profile_refuses_rather_than_falling_back() {
    use mcp_re_http_profile::scitt::StatementLeafProfile;

    let statement = SignedStatement::from_cose(&capsule("signed-statement.cbor")).expect("parses");
    let receipt = Receipt::from_cose(&capsule("receipt.cbor")).expect("parses");
    let pin: ScittServiceTrustPin =
        serde_json::from_slice(&capsule("service-key-pin.json")).expect("pin parses");
    assert_eq!(
        pin.leaf_profile(),
        StatementLeafProfile::StatementDigest,
        "capsule-anchor logs a digest of the statement"
    );

    let pin = pin_document_with(&capsule("service-key-pin.json"), |d| {
        d.insert("leaf_profile".into(), "statement-bytes".into());
    });
    let issuer = issuer();
    assert_eq!(
        verify_receipt_offline(
            &statement,
            &receipt,
            |_| Some(issuer.clone().into()),
            |kid| pin.resolve(kid)
        )
        .expect_err("the statement-bytes profile must not verify this service's receipt"),
        HttpProfileError::ReceiptInvalid,
    );
}

/// The corpus records the registration exchange and its limits — including that this was
/// a local run of an open-source service, not a production transparency service.
#[test]
fn the_capsule_anchor_corpus_records_the_exchange_and_its_limits() {
    let meta: serde_json::Value =
        serde_json::from_slice(&capsule("exchange-metadata.json")).expect("metadata parses");
    assert_eq!(meta["leaf_profile"], "statement-digest");
    assert!(meta["registration_request"]["path"]
        .as_str()
        .expect("path")
        .contains("register-statement"));
    assert!(meta["limits"].as_str().expect("limits").contains("LOCAL"));
    assert!(meta["leaf_profile_reason"]
        .as_str()
        .expect("reason")
        .contains("RFC 9162"));

    use sha2::Digest;
    let manifest: serde_json::Value =
        serde_json::from_slice(&capsule("manifest.json")).expect("manifest parses");
    for (name, expected) in manifest["artifacts"].as_object().expect("artifacts") {
        let actual = mcp_re_core::b64url_encode(&sha2::Sha256::digest(capsule(name)));
        assert_eq!(
            &actual,
            expected.as_str().expect("digest"),
            "{name} drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// capsule-anchor, OPERATED — the same service, run by somebody else.
// ---------------------------------------------------------------------------
//
// The corpus above is a LOCAL run of open-source code, and it says so: it establishes that
// two implementations agree, and nothing about a service anybody operates. This one is the
// public instance at `witness.agentactioncapsule.org`, which we do not run, do not
// configure and cannot restart. Our exact Signed Statement went to it over the network and
// its receipt is frozen here, so the verification is reproducible with the network gone.
//
// It is also where a documented finding turned out to be stale. The externalization census
// recorded this contract's response as `{entry_hash, leaf_index, tree_size}` and NO
// receipt; the service's published OpenAPI now makes `receipt_b64` REQUIRED, and the
// exchange returned one. And the live instance uses a leaf rule neither corpus had:
// `SHA256(0x00 ‖ SHA256(Sig_structure))`, which it calls `sig_structure` and which is a
// third reading of RFC 9162 §2.1's entry.

/// THE external-interoperability property: a Transparency Service somebody else operates
/// accepted our exact octets, and its receipt verifies here with no network at all.
#[test]
fn an_operated_transparency_services_receipt_verifies_offline() {
    verify_corpus(operated_capsule)
        .expect("the operated service's receipt verifies offline against the pinned key");
}

/// The third leaf profile is doing real work: NEITHER of the other two verifies this
/// receipt, so nothing is falling back and nothing is being tried in turn.
#[test]
fn neither_older_leaf_profile_verifies_the_operated_services_receipt() {
    use mcp_re_http_profile::scitt::StatementLeafProfile;

    let statement =
        SignedStatement::from_cose(&operated_capsule("signed-statement.cbor")).expect("parses");
    let receipt = Receipt::from_cose(&operated_capsule("receipt.cbor")).expect("parses");
    let pinned: ScittServiceTrustPin =
        serde_json::from_slice(&operated_capsule("service-key-pin.json")).expect("pin parses");
    assert_eq!(
        pinned.leaf_profile(),
        StatementLeafProfile::SigStructureDigest,
        "the operated instance logs a digest of the signing act",
    );

    let issuer = issuer();
    for wrong in ["statement-bytes", "statement-digest"] {
        let pin = pin_document_with(&operated_capsule("service-key-pin.json"), |d| {
            d.insert("leaf_profile".into(), wrong.into());
        });
        assert_eq!(
            verify_receipt_offline(
                &statement,
                &receipt,
                |_| Some(issuer.clone().into()),
                |kid| pin.resolve(kid)
            )
            .expect_err("a leaf rule this service does not use must not verify its receipt"),
            HttpProfileError::ReceiptInvalid,
            "{wrong}",
        );
    }
}

/// And the same receipt does NOT verify against the LOCAL instance's pin, or the local
/// receipt against this one's. Two deployments of one codebase are two services, and a
/// corpus that let either stand in for the other would be claiming more than it measured.
#[test]
fn the_two_capsule_anchor_deployments_do_not_verify_for_each_other() {
    let issuer = issuer();
    let operated_statement =
        SignedStatement::from_cose(&operated_capsule("signed-statement.cbor")).expect("parses");
    let operated_receipt = Receipt::from_cose(&operated_capsule("receipt.cbor")).expect("parses");
    let local_receipt = Receipt::from_cose(&capsule("receipt.cbor")).expect("parses");
    let local_pin: ScittServiceTrustPin =
        serde_json::from_slice(&capsule("service-key-pin.json")).expect("pin parses");
    let operated_pin: ScittServiceTrustPin =
        serde_json::from_slice(&operated_capsule("service-key-pin.json")).expect("pin parses");

    assert!(
        verify_receipt_offline(
            &operated_statement,
            &operated_receipt,
            |_| Some(issuer.clone().into()),
            |kid| local_pin.resolve(kid)
        )
        .is_err(),
        "the operated receipt must not verify under the local deployment's key",
    );
    assert!(
        verify_receipt_offline(
            &operated_statement,
            &local_receipt,
            |_| Some(issuer.clone().into()),
            |kid| operated_pin.resolve(kid)
        )
        .is_err(),
        "the local receipt must not verify under the operated deployment's key",
    );
}

/// The corpus states WHAT was exercised and what it does not earn — in particular that
/// this is not SCRAPI interoperability, and that the earlier "no receipt" finding is
/// superseded by an exchange rather than by a re-reading.
#[test]
fn the_operated_corpus_records_the_exchange_its_limits_and_what_it_supersedes() {
    let meta: serde_json::Value =
        serde_json::from_slice(&operated_capsule("exchange-metadata.json")).expect("parses");
    assert_eq!(meta["leaf_profile"], "sig-structure-digest");
    assert_eq!(
        meta["registration_response"]["entry_hash_scheme"],
        "sig_structure"
    );
    assert!(meta["peer_kind"]
        .as_str()
        .expect("peer_kind")
        .contains("OPERATED BY A THIRD PARTY"));
    let limits = meta["limits"].as_str().expect("limits");
    assert!(
        limits.contains("NOT SCRAPI interoperability"),
        "the corpus must not let this be read as the stronger claim: {limits}",
    );
    assert!(meta["supersedes"]
        .as_str()
        .expect("supersedes")
        .contains("NO RECEIPT"));

    use sha2::Digest;
    let manifest: serde_json::Value =
        serde_json::from_slice(&operated_capsule("manifest.json")).expect("manifest parses");
    assert_eq!(manifest["schema"], "mcp-re-scitt-interop/v1");
    for (name, expected) in manifest["artifacts"].as_object().expect("artifacts") {
        let actual = mcp_re_core::b64url_encode(&sha2::Sha256::digest(operated_capsule(name)));
        assert_eq!(
            &actual,
            expected.as_str().expect("digest"),
            "{name} drifted"
        );
    }
}

#[test]
#[ignore = "golden writer: regenerates the committed verification reports"]
fn write_verification_reports() {
    for (dir, peer) in corpora() {
        let report = build_report(&dir, &peer);
        std::fs::write(
            dir.join("verification-report.json"),
            serde_json::to_string_pretty(&report).expect("serialize") + "\n",
        )
        .expect("write report");
    }
}

/// The committed report is a record of what the verifier does NOW. Every verdict is
/// re-derived and every artifact re-hashed, so a report left behind by an older verifier
/// fails here instead of standing as evidence for behaviour that changed.
#[test]
fn the_committed_verification_reports_match_a_fresh_run() {
    for (dir, peer) in corpora() {
        let committed: VerificationReport = serde_json::from_slice(
            &std::fs::read(dir.join("verification-report.json"))
                .expect("verification-report.json committed"),
        )
        .expect("report parses");
        let fresh = build_report(&dir, &peer);

        assert_eq!(committed.schema, fresh.schema);
        assert_eq!(committed.peer, fresh.peer, "peer drifted");
        assert_eq!(
            committed.positive_verdict, "verify_ok",
            "the recorded positive must be a verification, not a refusal"
        );
        assert_eq!(
            committed.positive_verdict, fresh.positive_verdict,
            "the verifier no longer reaches the recorded verdict"
        );
        assert_eq!(
            committed.artifacts, fresh.artifacts,
            "artifact digests drifted"
        );
        assert_eq!(
            committed.refusals, fresh.refusals,
            "recorded refusals drifted"
        );
        assert!(
            committed.refusals.values().all(|v| v != "verify_ok"),
            "a refusal that verifies is not a refusal"
        );
        assert!(
            committed.refusals.len() >= 4,
            "the refusals are the substance of the report"
        );
    }
}
