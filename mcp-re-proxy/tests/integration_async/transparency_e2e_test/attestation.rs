// SPDX-License-Identifier: Apache-2.0
//! In-process attestation over what the serving path retained: reconstruct, issue the
//! statement, register, verify.

use super::fixtures::{
    assert_verifies_offline_under_prototype, attest, nobody, reconstruct, resolver, sign_with,
    ts_key, Scratch, TS_KID,
};
use super::server::{build_server, serve_one};
use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use mcp_re_http_profile::ChainLabel;
use mcp_re_proxy::transparency::EvidenceRetention;
use mcp_re_test_paths::unique_test_nonce;
use std::sync::Arc;

/// One served call, retained: the scratch, the serving handle on the store, and the
/// retained object's name and digest.
struct Retained {
    scratch: Scratch,
    retention: Arc<EvidenceRetention>,
    name: String,
    digest: EvidenceDigest,
}

fn serve_and_retain(scratch_name: &str) -> Retained {
    let scratch = Scratch::new(scratch_name);
    let retention = scratch.retention();
    let proxy = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&proxy, &unique_test_nonce()), 200);

    let name = scratch
        .retained_names()
        .into_iter()
        .next()
        .expect("one object");
    let digest = scratch.digest_of(&name);
    Retained {
        scratch,
        retention,
        name,
        digest,
    }
}

/// The whole vertical: serve, retain, reconstruct, attest, register, verify offline.
#[test]
fn a_served_call_becomes_an_offline_verifiable_receipt() {
    let scratch = Scratch::new("vertical");
    let proxy = build_server(Some(scratch.retention()));

    assert_eq!(serve_one(&proxy, &unique_test_nonce()), 200);

    // The auditor reads what the serving path kept. The handle is the store's, so an
    // auditor that has the digest — from the deployment's audit stream — can find it.
    let retained = scratch.retained_names();
    assert_eq!(
        retained.len(),
        1,
        "exactly the one served exchange was retained"
    );
    let digest = scratch.digest_of(&retained[0]);

    let attestation =
        attest(&scratch, &[digest], &resolver()).expect("the retained exchange attests");

    assert_eq!(
        attestation.reconstruction.label(),
        &ChainLabel::Complete,
        "a single terminal hop, fully verified, is a complete record"
    );
    assert!(attestation.statement.commitment().is_complete_record());

    // Registration, then the acceptance property: the receipt verifies CONTACTING
    // NOBODY.
    let mut service = PrototypeTransparencyService::new(TS_KID);
    let receipt = service
        .register(&attestation.statement, sign_with(ts_key()))
        .expect("the statement registers");

    assert_verifies_offline_under_prototype(
        &attestation.statement,
        &receipt,
        "the receipt verifies offline",
    );
}

/// The retained/committed split made to mean something: the statement's commitment is
/// checked against the bytes the store holds. A receipt says a statement was registered;
/// only this says the statement is about the evidence in hand.
#[test]
fn the_statement_is_verifiable_against_the_bytes_the_store_kept() {
    let Retained {
        scratch,
        retention,
        name,
        digest,
    } = serve_and_retain("retained");
    let attestation = attest(&scratch, std::slice::from_ref(&digest), &resolver()).expect("attest");

    // Re-derived independently from the store, as an auditor holding only the retained
    // bytes and the statement would.
    let reconstruction = reconstruct(&scratch, &[digest]);
    mcp_re_http_profile::scitt::verify_retained_evidence(
        attestation.statement.commitment(),
        &reconstruction,
        None,
        None,
    )
    .expect("the retained bytes reproduce what the statement committed to");

    // And the control: a DIFFERENT record does not pass as this one.
    let other = build_server(Some(retention));
    assert_eq!(serve_one(&other, &unique_test_nonce()), 200);
    let other_name = scratch
        .retained_names()
        .into_iter()
        .find(|n| n != &name)
        .expect("the second call was retained under its own name");
    let other_reconstruction = reconstruct(&scratch, &[scratch.digest_of(&other_name)]);
    assert!(
        mcp_re_http_profile::scitt::verify_retained_evidence(
            attestation.statement.commitment(),
            &other_reconstruction,
            None,
            None,
        )
        .is_err(),
        "a statement must not verify against a different call's retained evidence"
    );
}

/// R8-C030: the records with no verified hop are the ones an auditor most needs a
/// portable statement about, and they must be attestable.
///
/// `attest_chain` self-checks the statement it just issued against the retained bytes.
/// That check is over a record that NAMES bytes, and a reconstruction with no verified
/// prefix — the empty chain, and a chain that broke at hop 0 — names none: two empty
/// handles and a fold over nothing. Running it unconditionally made the function refuse
/// exactly the class its own contract says it must attest, so a submission whose first
/// hop failed to verify had no portable evidence at all.
#[test]
fn a_chain_with_no_verified_hop_is_still_attested() {
    let Retained {
        scratch, digest, ..
    } = serve_and_retain("no-verified-hop");

    let attestation = attest(&scratch, std::slice::from_ref(&digest), &nobody())
        .expect("a record whose first hop did not verify still gets a portable statement");

    assert!(
        matches!(
            attestation.reconstruction.label(),
            &ChainLabel::Incomplete { hop: 0, .. }
        ),
        "the label is what says which hop broke: {:?}",
        attestation.reconstruction.label()
    );
    assert!(
        attestation.reconstruction.hop_evidence().is_empty(),
        "nothing verified, so there is no verified prefix"
    );
    assert!(
        !attestation
            .statement
            .commitment()
            .commits_to_verified_evidence(),
        "the statement must say plainly that it names no verified evidence"
    );
    assert!(
        !attestation.statement.commitment().is_complete_record(),
        "and it must never read as a complete call record"
    );

    // The empty chain is the same class and must behave the same way.
    let empty = attest(&scratch, &[], &nobody())
        .expect("the empty chain is a representable record, not an error");
    assert!(!empty.statement.commitment().commits_to_verified_evidence());

    // The self-check is still applied where it means something: a statement about a
    // chain that DID verify is checked against the retained bytes.
    let complete = attest(&scratch, std::slice::from_ref(&digest), &resolver()).expect("attest");
    assert!(complete
        .statement
        .commitment()
        .commits_to_verified_evidence());
}
