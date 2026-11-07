// SPDX-License-Identifier: Apache-2.0
#![cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
//! The lane body shared by the AWS and GCP delegated-signing custody suites: drive the
//! ADR-MCPRE-052 custody state machine with a KMS signer as the ROOT issuer and prove zero
//! KMS ops on the per-request path, a verifiable attestation chain to the KMS root, rotation
//! overlap (no verification gap), and a fail-closed body tamper.
//!
//! Each suite owns what is provider-specific — how its live signer is constructed and what
//! its root `issuer_kid` is — and hands both here.

mod fixtures;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::KeyLifecycleEvent;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedDelegatedMcpResponse;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

use fixtures::{
    client_key, expectations, fresh_response, signed_request, AUD_SCOPE, EPOCH, NOW, OVERLAP, TTL,
    VERIFIER_AUD,
};

// A batch of per-request signs comfortably larger than 1, to prove the KMS is not
// touched per request.
const RESPONSES_PER_KEY: usize = 8;

type Custody = DelegatedSigningCustody<
    Box<dyn FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>>,
    Box<dyn FnMut() -> SigningKey>,
>;

/// A lane over one KMS root, named by the `issuer_kid` the verifier trusts. The delegated
/// key ids the custody mints are `<root_kid>/delegated/<n>`.
pub struct Lane<'a> {
    root_kid: &'a str,
}

impl<'a> Lane<'a> {
    pub fn over_root(root_kid: &'a str) -> Self {
        Self { root_kid }
    }

    /// Resolver: the client key for the Request slot, and the KMS ROOT public key
    /// (by its `issuer_kid`) for the Response slot — the credential's issuer is
    /// resolved for the Response slot. The DELEGATED key is NEVER enrolled here; it is
    /// authorized by the KMS-signed credential alone.
    fn resolver(
        &self,
        root_pub: VerificationKey,
    ) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + '_ {
        let client_pub = client_key().public_key();
        move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                ("client-key-1", SignerSlot::Request) => ("client", client_pub.clone()),
                (kid, SignerSlot::Response) if kid == self.root_kid => ("server", root_pub.clone()),
                _ => return None,
            };
            Some(ResolvedActor {
                identity: ActorIdentity {
                    role: role.into(),
                    trust_domain: "example.com".into(),
                    subject: format!("did:example:{role}"),
                    keyid: key_id.into(),
                },
                verification_key: key,
                slot,
            })
        }
    }

    fn custody_cfg(&self) -> CustodyConfig {
        CustodyConfig {
            issuer_kid: self.root_kid.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: VERIFIER_AUD.into(),
            audience_hash: AUD_SCOPE.into(),
            trust_epoch: EPOCH.parse().expect("epoch base"),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            window: DelegatedKeyWindow::of(TTL, OVERLAP).expect("0 < overlap < ttl"),
        }
    }

    /// Drive the custody state machine with `signer` as the KMS ROOT issuer.
    pub fn run(&self, signer: KmsResponseSigner) {
        let mut session = Session::start(self, signer);
        session.sign_a_batch_under_the_first_key();
        session.assert_the_kms_was_touched_once();
        session.assert_verifies(&session.predecessor, NOW, "before rotation");

        // Rotation: cross into the overlap window (now >= exp - overlap).
        // exp = NOW + TTL; rotation is due at NOW + TTL - OVERLAP. Sign past it.
        let after = NOW + TTL - OVERLAP + 10;
        let successor = session.rotate_at(after);
        session.assert_no_verification_gap(&successor, after);
        session.assert_the_lifecycle_was_audited();
        session.assert_a_tampered_body_fails_closed(after);
    }
}

/// One run of the lane: the custody under test, the KMS calls counted against it, and what
/// the steps carry from one to the next.
struct Session<'a> {
    lane: &'a Lane<'a>,
    req: HttpRequest,
    root_pub: VerificationKey,
    kms_calls: Arc<AtomicUsize>,
    custody: Custody,
    /// The response the first key signed, kept to re-verify across the rotation.
    predecessor: HttpResponse,
    first_kid: String,
    second_kid: String,
    lifecycle: Vec<KeyLifecycleEvent>,
}

impl<'a> Session<'a> {
    /// Wire the KMS backend as the custody root issuer through the wire-identical seam: the
    /// KMS signs the compact-JWS credential's signing input at issuance/rotation; the
    /// returned base64url raw Ed25519 signature is decoded to the 64 bytes the JWS carries.
    /// Then sign the first response, which issues the first delegated key.
    fn start(lane: &'a Lane<'a>, signer: KmsResponseSigner) -> Self {
        let req = signed_request();
        let root_pub = signer.response_public_key().expect("KMS root public key");

        // Count REAL KMS invocations: the issuer closure is the ONLY place the KMS is
        // touched, so a per-request sign that hit the KMS would bump this.
        let kms_calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&kms_calls);
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| -> Option<String> {
            issue_delegation_credential_with_signer(h, c, |input| {
                counted.fetch_add(1, Ordering::SeqCst);
                let b64 = signer
                    .sign_response(input)
                    .map_err(|_| HttpProfileError::InvalidSignature)?;
                b64url_decode(&b64).map_err(|_| HttpProfileError::InvalidSignature)
            })
            .ok()
        };
        // Deterministic in-memory delegated-key factory (a distinct key per rotation).
        let mut seed = 100u8;
        let factory = move || {
            seed = seed.wrapping_add(1);
            SigningKey::from_seed_bytes(&[seed; 32])
        };
        let mut custody: Custody = DelegatedSigningCustody::new(
            lane.custody_cfg(),
            root_pub.clone(),
            Box::new(issue),
            Box::new(factory),
        );

        let mut predecessor = fresh_response();
        custody
            .sign_response(NOW, &mut predecessor, &req)
            .expect("custody signs (issuance)");
        let first_kid = custody.active_kid().expect("a key is active").to_owned();
        let lifecycle = custody.step_events().to_vec();
        Self {
            lane,
            req,
            root_pub,
            kms_calls,
            custody,
            predecessor,
            first_kid,
            second_kid: String::new(),
            lifecycle,
        }
    }

    /// `rsp` through the delegated verifier, rooted at the KMS public key.
    fn verify(
        &self,
        rsp: &HttpResponse,
        now: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        Verifier::new(
            &VerifierPolicy::default(),
            &self.lane.resolver(self.root_pub.clone()),
        )
        .verify_delegated_bound_response(
            rsp,
            &self.req,
            &expectations(&[EPOCH]),
            &|_| false,
            now,
        )
    }

    fn assert_verifies(&self, rsp: &HttpResponse, now: i64, when: &str) {
        self.verify(rsp, now)
            .unwrap_or_else(|e| panic!("predecessor response verifies {when}: {e:?}"));
    }

    /// N per-request signs under one delegated key, each verifying via the KMS-rooted
    /// attestation chain.
    fn sign_a_batch_under_the_first_key(&mut self) {
        for _ in 1..RESPONSES_PER_KEY {
            let mut rsp = fresh_response();
            self.custody
                .sign_response(NOW, &mut rsp, &self.req)
                .expect("custody signs (hot path)");
            self.verify(&rsp, NOW)
                .expect("delegated response verifies via the KMS-rooted attestation chain");
        }
    }

    /// The load-bearing assertion: N responses signed, KMS touched exactly ONCE.
    fn assert_the_kms_was_touched_once(&self) {
        assert_eq!(
            self.kms_calls.load(Ordering::SeqCst),
            1,
            "the KMS root must be invoked ONLY at issuance — zero remote KMS ops on the per-request path"
        );
        assert_eq!(
            self.custody.root_invocations(),
            1,
            "custody must record exactly one root invocation across the whole batch"
        );
        assert_eq!(
            self.custody.root_invocations() as usize,
            self.kms_calls.load(Ordering::SeqCst),
            "every root invocation is exactly one KMS call — and no more"
        );
    }

    /// Sign past the rotation point: a distinct successor key is minted, which costs the
    /// KMS root exactly one more call.
    fn rotate_at(&mut self, after: i64) -> HttpResponse {
        let mut successor = fresh_response();
        self.custody
            .sign_response(after, &mut successor, &self.req)
            .expect("custody signs (rotation)");
        self.lifecycle.extend_from_slice(self.custody.step_events());
        self.second_kid = self
            .custody
            .active_kid()
            .expect("a successor key is active")
            .to_owned();
        assert_ne!(
            self.first_kid, self.second_kid,
            "rotation must mint a distinct delegated key"
        );
        assert_eq!(
            self.kms_calls.load(Ordering::SeqCst),
            2,
            "rotation invokes the KMS root exactly once more (successor credential)"
        );
        successor
    }

    /// No verification gap: the successor response verifies AND the predecessor — minted
    /// under the first key, still within its own TTL — is still accepted at the overlap
    /// instant (both keys simultaneously valid).
    fn assert_no_verification_gap(&self, successor: &HttpResponse, after: i64) {
        self.verify(successor, after)
            .expect("successor response verifies after rotation");
        self.verify(&self.predecessor, after)
            .expect("predecessor response still verifies during the overlap window (no gap)");
    }

    /// Audited lifecycle: issue then rotate.
    fn assert_the_lifecycle_was_audited(&self) {
        let audit = &self.lifecycle;
        assert_eq!(audit.len(), 2, "one issuance + one rotation audited");
        assert_eq!(audit[0].event_type(), "mcp-re.delegated_key.issued");
        assert_eq!(audit[0].delegated_kid(), self.first_kid);
        assert_eq!(audit[0].issuer_kid(), self.lane.root_kid);
        assert_eq!(audit[1].event_type(), "mcp-re.delegated_key.rotated");
        assert_eq!(audit[1].delegated_kid(), self.second_kid);
    }

    /// Negative: a body tamper on a delegated response fails closed.
    fn assert_a_tampered_body_fails_closed(&mut self, after: i64) {
        let mut tampered = fresh_response();
        self.custody
            .sign_response(after, &mut tampered, &self.req)
            .expect("custody signs");
        let last = tampered.body.len() - 2;
        tampered.body[last] ^= 0x01;
        assert_eq!(
            self.verify(&tampered, after).unwrap_err(),
            HttpProfileError::ContentDigestMismatch,
            "a post-signing body tamper on a delegated response must fail closed"
        );
    }
}
