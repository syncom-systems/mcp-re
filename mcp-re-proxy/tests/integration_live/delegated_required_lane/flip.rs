// SPDX-License-Identifier: Apache-2.0
//! LANE B — the authority flip, on ONE KMS key.
//!
//!   1. the PRE-052 authority (the KMS signs the response DIRECTLY, with no delegation
//!      evidence block) is REJECTED by a delegated-required verifier (fails closed) — no
//!      downgrade to the old response authority;
//!   2. the POST-052 authority (the KMS ISSUES a credential; an in-memory delegated key
//!      signs) is ACCEPTED;
//!   3. a TRUST-EPOCH flip: a KMS-rooted credential minted under the old epoch is rejected
//!      once the accepted-epoch set advances (`delegation_trust_epoch_stale`), and accepted
//!      under a bounded-rollout `{new, old}` window;
//!   4. a KEY-authority rotation + revocation flip: after the KMS issues a successor,
//!      revoking the predecessor kid fails its responses closed (`delegation_revoked`) while
//!      the successor's still verify.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::sign_response_with_signer;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResponseSignature;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

use super::fixtures::fresh_response;
use super::fixtures::overlap_instant;
use super::fixtures::signed_request;
use super::fixtures::EPOCH;
use super::fixtures::NEW_EPOCH;
use super::fixtures::NOW;
use super::judge::Exchange;
use super::judge::Judge;
use super::Lane;

type IssueCredential = Box<dyn FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>>;
type MintKey = Box<dyn FnMut() -> SigningKey>;
type KmsCustody = DelegatedSigningCustody<IssueCredential, MintKey>;

/// The KMS `signer`'s raw signature over `input`, decoded.
fn kms_signature(signer: &KmsResponseSigner, input: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    let b64 = signer
        .sign_response(input)
        .map_err(|_| HttpProfileError::InvalidSignature)?;
    b64url_decode(&b64).map_err(|_| HttpProfileError::InvalidSignature)
}

/// A custody state machine whose ROOT issuer is the KMS `signer`, plus a shared KMS-call
/// counter, so the flip lane can mint KMS-rooted delegated responses.
fn kms_custody(lane: &Lane, signer: KmsResponseSigner, kms_calls: Arc<AtomicUsize>) -> KmsCustody {
    let root_pub = signer.response_public_key().expect("KMS root public key");
    let issue: IssueCredential = Box::new(move |h, c| {
        issue_delegation_credential_with_signer(h, c, |input| {
            kms_calls.fetch_add(1, Ordering::SeqCst);
            kms_signature(&signer, input)
        })
        .ok()
    });
    let mut seed = 100u8;
    let factory: MintKey = Box::new(move || {
        seed = seed.wrapping_add(1);
        SigningKey::from_seed_bytes(&[seed; 32])
    });
    DelegatedSigningCustody::new(lane.custody_cfg(), root_pub, issue, factory)
}

/// Flip 1: the SAME KMS key that (post-052) issues credentials signs a response directly,
/// with NO inline credential, exactly as a pre-052 direct-root server would; a
/// delegated-required verifier refuses it — no downgrade.
fn assert_direct_root_response_refused(
    lane: &Lane,
    root: &KmsResponseSigner,
    judge: &Judge<'_>,
    req: &HttpRequest,
) {
    let mut direct = fresh_response();
    sign_response_with_signer(
        &mut direct,
        req,
        |base| kms_signature(root, base),
        &ResponseSignature {
            key_id: lane.root_kid,
            created: NOW - 100,
            expires: NOW + 200,
        },
    )
    .expect("the KMS signs a direct-root RFC 9421 response");
    let downgrade = judge
        .verify(
            &Exchange {
                request: req,
                response: &direct,
            },
            NOW,
        )
        .unwrap_err();
    // A genuine pre-052 direct-root response carries NO delegation evidence block at
    // all (unlike a delegation block with the credential stripped), so it fails
    // closed here. Fail-closed rejection is the property; the exact code is
    // MissingEvidence for this shape.
    assert!(
        matches!(downgrade, HttpProfileError::MissingEvidence(_)),
        "flipping response authority to delegated-required REJECTS a pre-052 direct-root \
         response (no delegation evidence block); got {downgrade:?}"
    );
}

/// The custody the KMS roots, the request every flip answers, and the judge of the answers.
struct Flip<'a> {
    judge: Judge<'a>,
    req: HttpRequest,
    custody: KmsCustody,
    kms_calls: Arc<AtomicUsize>,
}

impl Flip<'_> {
    fn exchange<'r>(&'r self, response: &'r HttpResponse) -> Exchange<'r> {
        Exchange {
            request: &self.req,
            response,
        }
    }

    /// A fresh response signed by the custody at `at`.
    fn sign_at(&mut self, at: i64, why: &str) -> HttpResponse {
        let mut response = fresh_response();
        self.custody
            .sign_response(at, &mut response, &self.req)
            .expect(why);
        response
    }

    fn active_kid(&self, why: &str) -> String {
        self.custody.active_kid().expect(why).to_owned()
    }

    fn assert_kms_issued(&self, count: usize, why: &str) {
        assert_eq!(self.kms_calls.load(Ordering::SeqCst), count, "{why}");
    }

    /// Flip 2 (post-052 authority accepted): the KMS issues the credential. Returns the
    /// response and the kid of the key that signed it.
    fn assert_delegated_authority_accepted(&mut self) -> (HttpResponse, String) {
        let delegated = self.sign_at(NOW, "KMS-rooted custody signs");
        let first_kid = self.active_kid("a key is active");
        self.assert_kms_issued(1, "the KMS issued exactly one credential");
        self.judge
            .verify(&self.exchange(&delegated), NOW)
            .expect("the delegated (post-052) authority is accepted");
        (delegated, first_kid)
    }

    /// Flip 3: the credential is bound to EPOCH. Advancing the accepted set to NEW_EPOCH
    /// alone rejects it; a bounded-rollout {new, old} window accepts it (ADR-MCPRE-052 §7).
    fn assert_epoch_flip(&self, delegated: &HttpResponse) {
        let exchange = self.exchange(delegated);
        let stale = self
            .judge
            .verify_under_epochs(&exchange, &[NEW_EPOCH], NOW)
            .unwrap_err();
        assert_eq!(
            stale,
            HttpProfileError::DelegationTrustEpochStale,
            "advancing the trust epoch rejects a credential minted under the old authority epoch"
        );
        self.judge
            .verify_under_epochs(&exchange, &[NEW_EPOCH, EPOCH], NOW)
            .expect("a bounded-rollout {new, old} epoch window accepts the old-epoch credential");
    }

    /// Flip 4: the KMS issues a successor; revoking the predecessor kid fails its responses
    /// closed while the successor's verify. The predecessor response was minted at NOW;
    /// re-sign a fresh one so both keys are simultaneously within their TTL at the overlap
    /// instant.
    fn assert_rotation_and_revocation(&mut self, first_kid: &str) {
        let predecessor = self.sign_at(NOW, "predecessor signs");
        let after = overlap_instant();
        let successor = self.sign_at(after, "KMS issues the successor");
        let second_kid = self.active_kid("successor active");
        assert_ne!(
            first_kid, second_kid,
            "rotation mints a distinct delegated authority"
        );
        self.assert_kms_issued(2, "the KMS issued exactly two credentials total");

        // Revoke the PREDECESSOR authority. The successor still verifies; the predecessor
        // fails closed — a revoked authority cannot serve even during the overlap.
        let revoke_first = |id: &str| id == first_kid;
        self.judge
            .verify_revoking(&self.exchange(&successor), &revoke_first, after)
            .expect(
                "the successor (new authority) still verifies while the predecessor is revoked",
            );
        let revoked = self
            .judge
            .verify_revoking(&self.exchange(&predecessor), &revoke_first, after)
            .unwrap_err();
        assert_eq!(
            revoked,
            HttpProfileError::DelegationRevoked,
            "revoking the predecessor authority fails its responses closed"
        );
    }
}

pub(crate) fn run_flip(lane: &Lane, root: KmsResponseSigner) {
    let judge = Judge::new(
        lane,
        root.response_public_key().expect("KMS root public key"),
    );
    let req = signed_request(&mcp_re_test_paths::unique_test_nonce(), NOW);
    assert_direct_root_response_refused(lane, &root, &judge, &req);

    let kms_calls = Arc::new(AtomicUsize::new(0));
    let custody = kms_custody(lane, root, Arc::clone(&kms_calls));
    let mut flip = Flip {
        judge,
        req,
        custody,
        kms_calls,
    };
    let (delegated, first_kid) = flip.assert_delegated_authority_accepted();
    flip.assert_epoch_flip(&delegated);
    flip.assert_rotation_and_revocation(&first_kid);
}
