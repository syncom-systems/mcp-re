// SPDX-License-Identifier: Apache-2.0
//! LANE A — the PRODUCTION serving path on the KMS root.
//!
//! The KMS root is wrapped in a counting `ResponseSigner` so the load-bearing property is
//! asserted at the SERVING altitude: N served responses invoke the KMS ZERO extra times
//! (one op per key issuance/rotation, none per request). The lane also proves rotation to a
//! successor and the client revocation seam (allow + deny) on a KMS-rooted credential.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::http_profile_dispatch::ReplayAdmission;
use mcp_re_proxy::http_profile_dispatch::ReplayPosture;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedSigningWiring;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_proxy::KeyError;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

use super::fixtures::canned_inner;
use super::fixtures::http_response;
use super::fixtures::overlap_instant;
use super::fixtures::served_of;
use super::fixtures::signed_request;
use super::fixtures::signing_plan;
use super::fixtures::NOW;
use super::fixtures::RESPONSES_PER_KEY;
use super::judge::Exchange;
use super::judge::Judge;
use super::Lane;

/// A `ResponseSigner` that wraps the KMS root and counts EVERY real signing call.
/// Passing this as the root to `build_delegated_signing` lets the SERVING lane
/// assert the KMS is invoked only at issuance/rotation — never on the request path.
struct CountingRootSigner {
    inner: KmsResponseSigner,
    calls: Arc<AtomicUsize>,
}

impl ResponseSigner for CountingRootSigner {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.inner.response_public_key()
    }
}

/// The serving proxy built EXACTLY as `app::run` builds it in delegated-required mode, the
/// root's KMS-call counter, and the judge of what it serves.
struct Rig<'a> {
    lane: &'a Lane,
    wiring: DelegatedSigningWiring,
    proxy: HttpProfileProxy,
    kms_calls: Arc<AtomicUsize>,
    judge: Judge<'a>,
}

impl<'a> Rig<'a> {
    /// `build_delegated_signing` off the KMS root, then `new_delegated`.
    fn start(lane: &'a Lane, root: KmsResponseSigner) -> Self {
        let root_pub = root.response_public_key().expect("KMS root public key");
        let kms_calls = Arc::new(AtomicUsize::new(0));
        let counting = CountingRootSigner {
            inner: root,
            calls: Arc::clone(&kms_calls),
        };
        let config = lane.delegated_config();
        let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), counting)
            .expect("the root states its key");
        let expected_audience = AudienceTuple {
            audience_id: config.audience.clone(),
            target_uri: config.target_uri.clone(),
            route: config.route.clone(),
        };
        let proxy = HttpProfileProxy::new_delegated(
            fixture_resolver(lane, root_pub.clone()),
            expected_audience,
            ReplayAdmission::new(
                AsyncReplayTier::new(
                    Arc::new(InMemoryAsyncAtomicReplayStore::new()),
                    mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
                ),
                ReplayPosture::SingleProcess,
            ),
            canned_inner(),
            300,
            Arc::clone(&wiring.signer),
        );
        Rig {
            lane,
            wiring,
            proxy,
            kms_calls,
            judge: Judge::new(lane, root_pub),
        }
    }

    fn assert_kms_calls(&self, expected: usize, why: &str) {
        assert_eq!(self.kms_calls.load(Ordering::SeqCst), expected, "{why}");
    }

    async fn serve(&self, req: &HttpRequest, at: i64) -> HttpResponse {
        http_response(self.proxy.handle(served_of(req), at).await)
    }

    fn published_kid(&self, at: i64) -> String {
        self.wiring
            .signer
            .current(at)
            .expect("a key is published")
            .delegated_kid()
            .to_owned()
    }

    /// Startup issuance: the KMS signs the FIRST credential (one KMS op). Returns its kid.
    fn startup_issuance(&mut self) -> String {
        self.wiring
            .rotor
            .rotate(NOW)
            .expect("startup issuance mints the first delegated key via the KMS root");
        self.assert_kms_calls(1, "startup issuance is exactly one KMS op");
        let snap = self.wiring.signer.current(NOW).expect("a key is published");
        let first_kid = snap.delegated_kid().to_owned();
        // Profile-issued kids are RFC 7638 JWK thumbprints, derived from the delegated
        // key itself rather than an issuer counter.
        assert_eq!(
            first_kid,
            mcp_re_http_profile::jwk_thumbprint_ed25519(&snap.public_key().to_b64url()),
        );
        first_kid
    }

    /// Serve a batch under the one delegated key; each response verifies via the
    /// credential→KMS-root chain, signed by the DELEGATED key (not the root).
    async fn serve_batch_signed_by(&self, kid: &str) {
        for i in 0..RESPONSES_PER_KEY {
            let req = signed_request(&format!("nonce-serve-{i}"), NOW);
            let resp = self.serve(&req, NOW).await;
            assert_eq!(resp.status, 200, "delegated-required request served");
            let verified = self
                .judge
                .verify(
                    &Exchange {
                        request: &req,
                        response: &resp,
                    },
                    NOW,
                )
                .expect("served response verifies via the KMS-rooted attestation chain");
            assert_eq!(
                verified.signature_facts().accepted_signer.identity.keyid,
                kid,
                "signed by the delegated key, not the KMS root"
            );
        }
    }

    /// THE load-bearing property at the serving altitude: N responses, KMS untouched beyond
    /// the single issuance.
    fn assert_hot_path_never_reaches_kms(&self) {
        self.assert_kms_calls(
            1,
            &format!(
                "serving {RESPONSES_PER_KEY} responses invoked {} ZERO extra times — no KMS on the hot path",
                self.lane.kms
            ),
        );
    }

    /// Revocation seam: the client denylists the active delegated kid and the otherwise-valid
    /// response fails closed; a non-empty denylist that does NOT name this kid still verifies.
    async fn assert_revocation_seam(&self, kid: &str) {
        let req = signed_request(&mcp_re_test_paths::unique_test_nonce(), NOW);
        let resp = self.serve(&req, NOW).await;
        let exchange = Exchange {
            request: &req,
            response: &resp,
        };
        let deny = self
            .judge
            .verify_revoking(&exchange, &|id: &str| id == kid, NOW)
            .unwrap_err();
        assert_eq!(
            deny,
            HttpProfileError::DelegationRevoked,
            "revoked delegated kid fails closed"
        );
        self.judge
            .verify_revoking(&exchange, &|id: &str| id == "some-other/delegated/9", NOW)
            .expect("a non-matching denylist does not blanket-deny");
    }

    /// Rotation: cross into the overlap window → the KMS signs the SUCCESSOR credential (one
    /// more KMS op), and the new response verifies under it.
    async fn assert_rotation_to_successor(&mut self, first_kid: &str) {
        let after = overlap_instant();
        self.wiring
            .rotor
            .rotate(after)
            .expect("rotation mints a successor via the KMS root");
        self.assert_kms_calls(2, "rotation is exactly one more KMS op");
        let second_kid = self.published_kid(after);
        assert_ne!(
            first_kid, second_kid,
            "rotation mints a distinct delegated key"
        );
        let req = signed_request(&mcp_re_test_paths::unique_test_nonce(), after);
        let resp = self.serve(&req, after).await;
        let verified = self
            .judge
            .verify(
                &Exchange {
                    request: &req,
                    response: &resp,
                },
                after,
            )
            .expect("post-rotation response verifies");
        assert_eq!(
            verified.signature_facts().accepted_signer.identity.keyid,
            second_kid,
            "post-rotation responses are signed by the successor delegated key"
        );
    }
}

/// This fixture resolver is healthy by construction and knows exactly two bindings, so a
/// miss is a DEFINITIVE negative: NotTrusted, never Unavailable. The two are not
/// interchangeable — they surface as `mcp-re.actor_binding_failed` versus
/// `mcp-re.trust_resolver_unavailable` — so the choice is made here rather than left to a
/// blanket `Option` conversion that would silently pick one.
fn fixture_resolver(lane: &Lane, root_pub: VerificationKey) -> ActorResolver {
    let resolve = lane.resolver(root_pub);
    Box::new(move |k: &str, s| match resolve(k, s) {
        Some(actor) => ResolverOutcome::Resolved(Box::new(actor)),
        None => ResolverOutcome::NotTrusted,
    })
}

pub(crate) async fn run_serving(lane: &Lane, root: KmsResponseSigner) {
    let mut rig = Rig::start(lane, root);
    let first_kid = rig.startup_issuance();
    rig.serve_batch_signed_by(&first_kid).await;
    rig.assert_hot_path_never_reaches_kms();
    rig.assert_revocation_seam(&first_kid).await;
    rig.assert_rotation_to_successor(&first_kid).await;
}
