// SPDX-License-Identifier: Apache-2.0
//! MCPRE-122 — delegated-signing end-to-end battery (ADR-MCPRE-052 §3).
//!
//! A full request → delegated-key response round trip: the root mints a compact
//! JWS delegation credential, the DELEGATED key signs the RFC 9421 response, and
//! `Verifier::verify_delegated_bound_response` verifies the credential chain to the root and
//! the response signature under `cnf.jwk`. Covers the response-path rulings:
//! required delegation mode (§3 step 1) and the `keyid == delegated_kid` /
//! sign-under-`cnf.jwk` check (§3 step 8). Credential-scope checks (aud, profile,
//! audience-hash, key-use, trust-epoch, revocation) are unit-tested in
//! `delegation.rs`.

#[path = "delegation_e2e_test/fixtures.rs"]
mod fixtures;
#[path = "delegation_e2e_test/signing.rs"]
mod signing;
#[path = "delegation_e2e_test/verify.rs"]
mod verify;

use fixtures::{
    attacker_key, credential_scoped_to_another_keyid, custody_cfg, delegated_key, expectations,
    json_response, root_key, root_signer, seam_without_the_root, server_signer, sign_a_request,
    signed_request, valid_credential, CREATED, DELEGATED_KID, EPOCH, EXPIRES, NOW, ROOT_KID,
};
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::rejection::pre_052_direct_root::sign_pre_052_direct_root_response_for_negative_test;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use signing::{
    add_content_encoding, bound_response_signed_by, flip_a_body_byte, forge_bound,
    forge_bound_over_valid_credential, forge_unbound, make_event_stream,
    root_signed_without_a_credential, signed_delegated_bound, signed_delegated_unbound,
    unbound_receipt_signed_by, uncover_the_req_method, Forgery,
};
use verify::{
    assert_bound_refused, assert_damaged_bound_refused, assert_damaged_unbound_refused,
    assert_unbound_refused, past_the_window, verify_bound, verify_unbound, Checks,
};

// --- positive ---------------------------------------------------------------

#[test]
fn valid_delegated_response_verifies_under_cnf_key() {
    let (req, _, _verified_req) = signed_request();
    let rsp = bound_response_signed_by(&req, delegated_key());

    let rv = verify_bound(&rsp, &req, Checks::STANDARD).expect("delegated response verifies");
    // The accepted signer is the delegated identity, authorized via the credential
    // chain (its verification key is the delegated key).
    assert_eq!(
        rv.signature_facts().accepted_signer.identity.keyid,
        DELEGATED_KID
    );
    assert_eq!(
        rv.signature_facts()
            .accepted_signer
            .verification_key
            .to_bytes(),
        delegated_key().public_key().to_bytes()
    );
}

// --- required mode (step 1) -------------------------------------------------

#[test]
fn direct_root_signed_response_is_rejected_credential_missing() {
    // A response signed directly by the root (server) key with NO delegation
    // credential must be rejected in required mode.
    let (req, ev, _verified_req) = signed_request();
    let mut rsp = json_response(200);
    // server_signer keyid is the ROOT here, and sign under the root key directly.
    sign_pre_052_direct_root_response_for_negative_test(
        &mut rsp,
        &req,
        &ev,
        &root_signer(),
        &root_key(),
        ROOT_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign direct-root response");

    assert_bound_refused(
        &rsp,
        &req,
        Checks::STANDARD,
        HttpProfileError::DelegationCredentialMissing,
    );
}

// --- step 8: keyid / cnf binding --------------------------------------------

#[test]
fn response_keyid_not_delegated_kid_is_key_mismatch() {
    // The credential authorizes DELEGATED_KID, but the response signature is made
    // under a different RFC 9421 keyid.
    let (req, _, verified_req) = signed_request();
    let credential = valid_credential();
    let rsp = forge_bound(
        &req,
        verified_req.evidence(),
        &Forgery {
            wire_kid: "some-other-kid", // RFC 9421 keyid ≠ delegated_kid
            ..Forgery::honest(&server_signer(), &credential)  // block keyid == DELEGATED_KID
        },
    );
    assert_bound_refused(
        &rsp,
        &req,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

#[test]
fn response_signed_by_key_other_than_cnf_is_key_mismatch() {
    // The response is signed by an ATTACKER key while claiming DELEGATED_KID; the
    // signature does not verify under cnf.jwk.
    let (req, _, _verified_req) = signed_request();
    let rsp = bound_response_signed_by(&req, attacker_key(99));
    assert_bound_refused(
        &rsp,
        &req,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

// --- body tamper (content-digest floor) -------------------------------------

#[test]
fn body_tamper_is_caught_by_content_digest() {
    // Flip a byte in the covered body.
    assert_damaged_bound_refused(flip_a_body_byte, HttpProfileError::ContentDigestMismatch);
}

// --- trust epoch (step 6), end-to-end ---------------------------------------

#[test]
fn stale_epoch_rejected_end_to_end() {
    let (req, _, _verified_req) = signed_request();
    // The credential is minted under EPOCH; the verifier's accepted set has advanced past it.
    let rsp = bound_response_signed_by(&req, delegated_key());
    let advanced = Checks {
        epochs: &["epoch-2"],
        ..Checks::STANDARD
    };
    assert_bound_refused(
        &rsp,
        &req,
        advanced,
        HttpProfileError::DelegationTrustEpochStale,
    );
}

// --- custody-produced response (slice 4), end-to-end ------------------------

/// The full chain: the custody state machine issues a delegated key + credential
/// and signs a response; a verifier accepts it via the attestation chain to the
/// root, and the root was touched exactly once (issuance), never per request.
#[test]
fn custody_signed_response_verifies_via_attestation_chain() {
    let (req, _, _verified_req) = signed_request();
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut custody =
        DelegatedSigningCustody::new(custody_cfg(), root_key().public_key(), issue, factory);

    let mut rsp = json_response(200);
    custody
        .sign_response(NOW, &mut rsp, &req)
        .expect("custody signs");

    let rv = verify_bound(&rsp, &req, Checks::STANDARD).expect("custody-signed response verifies");
    // A custody-issued key is profile-issued, so its kid is the RFC 7638 JWK
    // thumbprint of the key itself (#415 rev 2 §1.5). The key factory above hands
    // out seed [101; 32] first, so the kid is that key's thumbprint — derived from
    // the key material, not from an issuance counter.
    let first_issued = SigningKey::from_seed_bytes(&[101u8; 32]);
    assert_eq!(
        rv.signature_facts().accepted_signer.identity.keyid,
        mcp_re_http_profile::jwk_thumbprint_ed25519(&first_issued.public_key().to_b64url()),
    );
    assert_eq!(
        custody.root_invocations(),
        1,
        "root touched only at issuance"
    );
}

// --- revocation (step 7), end-to-end ----------------------------------------

#[test]
fn revoked_delegated_key_rejected_end_to_end() {
    let (req, _, _verified_req) = signed_request();
    let rsp = bound_response_signed_by(&req, delegated_key());
    let revoked = Checks {
        revoked_kid: Some(DELEGATED_KID),
        ..Checks::STANDARD
    };
    assert_bound_refused(&rsp, &req, revoked, HttpProfileError::DelegationRevoked);
}

/// A delegated PREFLIGHT receipt verifies with no request context at all, and says so in
/// its type: `VerifiedDelegatedUnboundResponse` carries no request binding to misread.
///
/// The operation had no in-crate test before the theorem registry needed one. Its evidence
/// lived only in a proxy integration test, which is a different unit — so the claim about
/// this operation had nothing resolvable behind it.
#[test]
fn a_delegated_preflight_receipt_verifies_without_request_binding() {
    let (req, _ev, _verified_req) = signed_request();
    let rsp = unbound_receipt_signed_by(&req, delegated_key());

    let rv =
        verify_unbound(&rsp, Checks::STANDARD).expect("the preflight receipt verifies unbound");
    assert_eq!(
        rv.signature_facts().accepted_signer.identity.keyid,
        DELEGATED_KID
    );
    assert_eq!(rv.delegation_issuer_kid(), ROOT_KID);
}

/// Delegation stays REQUIRED on the unbound path: a receipt with no inline credential —
/// including a directly root-signed one — is refused rather than accepted more leniently
/// because there is no request to bind to.
#[test]
fn an_unbound_receipt_without_a_credential_is_refused() {
    let (req, _ev, _verified_req) = signed_request();
    let receipt = unbound_receipt_signed_by(&req, delegated_key());
    let plain = root_signed_without_a_credential(&receipt);

    assert_unbound_refused(
        &plain,
        Checks::STANDARD,
        HttpProfileError::DelegationCredentialMissing,
    );
}

// --- the delegated conjuncts that had no control of their own ---------------

/// The delegated BOUND path makes the same explicit `request_evidence` comparison the
/// direct full path makes, and it is load-bearing there too. The `;req` floor cannot
/// substitute for it: here the `;req` binding is to `req_a` and verifies, while the block
/// advertises a different exchange's handle.
#[test]
fn a_delegated_response_advertising_another_requests_evidence_is_refused() {
    let (req_a, _ev_a, verified_a) = signed_request();

    // A second, genuinely different request → a different evidence handle.
    let (_req_b, ev_b) = sign_a_request();
    assert_ne!(ev_b.digest_value(), verified_a.evidence().digest_value());

    // ;req is bound to req_a; the block advertises req_b's handle.
    let rsp = forge_bound_over_valid_credential(&req_a, &ev_b);

    assert_bound_refused(
        &rsp,
        &req_a,
        Checks::STANDARD,
        HttpProfileError::ResponseBindingMismatch,
    );
}

/// The cnf.jwk signature check on the UNBOUND delegated path. `an_unbound_receipt_without_a_credential_is_refused`
/// fails at step 1 and says nothing about whether the signature is ever checked; this
/// presents a complete, valid credential and signs under an attacker key.
#[test]
fn an_unbound_receipt_signed_by_a_key_other_than_cnf_is_key_mismatch() {
    let (req, _ev, _verified_req) = signed_request();
    // keyid matches the credential; the key does not
    let rsp = unbound_receipt_signed_by(&req, attacker_key(98));

    assert_unbound_refused(
        &rsp,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

/// A `;req` component is refused on the delegated unbound path for the same reason it is
/// refused on the seam-authorized one: a verified credential chain does not conjure a
/// request to resolve the reference against.
#[test]
fn a_req_component_is_refused_on_the_delegated_unbound_path() {
    let (req, _, _verified_req) = signed_request();
    let rsp = bound_response_signed_by(&req, delegated_key());

    assert_unbound_refused(
        &rsp,
        Checks::STANDARD,
        HttpProfileError::MalformedEvidence("req component without request context"),
    );
}

/// Content-digest verification stays load-bearing on the unbound delegated path — the
/// credential is carried INSIDE the covered body, so a digest check that stopped
/// mattering would let the credential itself be swapped.
#[test]
fn an_unbound_receipt_body_tamper_is_caught_by_content_digest() {
    assert_damaged_unbound_refused(flip_a_body_byte, HttpProfileError::ContentDigestMismatch);
}

/// The unbound delegated path resolves the credential's ROOT ISSUER through the same
/// trust seam every other path uses, and a root nobody vouches for is refused. This is
/// the unbound counterpart of the chain's trust anchor: without it a self-issued
/// credential would authorize its own signer.
#[test]
fn an_unbound_receipt_whose_root_is_unknown_to_the_seam_is_untrusted() {
    let (req, _ev, _verified_req) = signed_request();
    let rsp = unbound_receipt_signed_by(&req, delegated_key());

    let err = Verifier::new(&VerifierPolicy::default(), &seam_without_the_root())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationIssuerUntrusted);
}

#[test]
fn a_block_naming_a_keyid_the_credential_did_not_confirm_is_key_mismatch() {
    let (req, _, verified_req) = signed_request();
    let (credential, disowned) = credential_scoped_to_another_keyid();
    // block keyid == the credential's subject binding, not its cnf kid;
    // wire keyid == the credential's delegated kid
    let rsp = forge_bound(
        &req,
        verified_req.evidence(),
        &Forgery::honest(&disowned, &credential),
    );

    assert_bound_refused(
        &rsp,
        &req,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

/// The same correspondence conjunct on the unbound path, where there is no request
/// evidence to cross-check the attribution against either.
#[test]
fn an_unbound_receipt_naming_a_keyid_the_credential_did_not_confirm_is_key_mismatch() {
    let (req, _ev, _verified_req) = signed_request();
    let (credential, disowned) = credential_scoped_to_another_keyid();
    let rsp = forge_unbound(&req, &Forgery::honest(&disowned, &credential));

    assert_unbound_refused(
        &rsp,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

/// The unbound analogue of `response_keyid_not_delegated_kid_is_key_mismatch`: the RFC 9421
/// wire keyid must be the credential's delegated kid, not merely a keyid whose signature
/// happens to verify under `cnf.jwk`.
///
/// The block names the confirmed kid and the signature verifies under the confirmed key,
/// so nothing else objects; only the wire-keyid comparison refuses it. Without it a
/// receipt could advertise an unconfirmed keyid on the wire — the coordinate a peer
/// caches, pins and reports — while presenting a credential for a different one.
#[test]
fn an_unbound_receipt_whose_wire_keyid_is_not_the_delegated_kid_is_key_mismatch() {
    let (req, _ev, _verified_req) = signed_request();
    // Block keyid == the credential's delegated kid, signed by the confirmed key, but
    // advertised on the wire under a keyid the credential never confirmed.
    let credential = valid_credential();
    let rsp = forge_unbound(
        &req,
        &Forgery {
            wire_kid: "some-other-kid",
            ..Forgery::honest(&server_signer(), &credential)
        },
    );

    assert_unbound_refused(
        &rsp,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

// --- the delegated preamble gates, on both delegated paths -------------------

#[test]
fn a_delegated_bound_response_with_a_content_encoding_is_refused() {
    assert_damaged_bound_refused(
        add_content_encoding,
        HttpProfileError::ContentEncodingPresent,
    );
}

#[test]
fn a_delegated_bound_response_that_is_not_json_is_refused() {
    assert_damaged_bound_refused(make_event_stream, HttpProfileError::NonJsonMediaType);
}

#[test]
fn a_delegated_bound_response_outside_its_signature_window_is_refused() {
    let (req, rsp) = signed_delegated_bound();
    assert_bound_refused(
        &rsp,
        &req,
        Checks::STANDARD.at(past_the_window()),
        HttpProfileError::StaleWindow,
    );
}

#[test]
fn a_delegated_bound_response_not_covering_a_req_component_is_refused() {
    assert_damaged_bound_refused(
        uncover_the_req_method,
        HttpProfileError::MissingCoveredComponent("@method"),
    );
}

#[test]
fn a_delegated_bound_response_whose_req_binding_is_to_another_request_is_refused() {
    let (req_a, _ev_a, _verified_a) = signed_request();
    let (mut req_b, ev_b) = sign_a_request();
    // A covered request component that differs from req_a's, so ;req cannot resolve alike.
    req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
    // ;req resolves over req_a while the block carries req_b's handle, and the response is
    // verified against req_b: the block-handle comparison agrees, only ;req can refuse.
    let rsp = forge_bound_over_valid_credential(&req_a, &ev_b);
    assert_bound_refused(
        &rsp,
        &req_b,
        Checks::STANDARD,
        HttpProfileError::DelegationKeyMismatch,
    );
}

#[test]
fn an_unbound_receipt_with_a_content_encoding_is_refused() {
    assert_damaged_unbound_refused(
        add_content_encoding,
        HttpProfileError::ContentEncodingPresent,
    );
}

#[test]
fn an_unbound_receipt_that_is_not_json_is_refused() {
    assert_damaged_unbound_refused(make_event_stream, HttpProfileError::NonJsonMediaType);
}

#[test]
fn an_unbound_receipt_outside_its_signature_window_is_refused() {
    let rsp = signed_delegated_unbound();
    assert_unbound_refused(
        &rsp,
        Checks::STANDARD.at(past_the_window()),
        HttpProfileError::StaleWindow,
    );
}
