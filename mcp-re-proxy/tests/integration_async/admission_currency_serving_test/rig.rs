// SPDX-License-Identifier: Apache-2.0
//! One fleet replica behind the production PEP, with the means to call it and read what it
//! recorded.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::admission_enforcer::AdmissionEnforcement;
use mcp_re_proxy::admission_enforcer::AdmissionFacet;
use mcp_re_proxy::admission_enforcer::AdmissionRefusalClass;
use mcp_re_proxy::admission_source::AsyncAdmissionSource;
use mcp_re_proxy::admission_source::InMemoryAdmissionSource;
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_dispatch::ReplayAdmission;
use mcp_re_proxy::http_profile_dispatch::ReplayPosture;
use mcp_re_proxy::CollectingAuditSink;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_test_paths::unique_test_nonce;

use super::fixtures::actor_resolver;
use super::fixtures::admission_claims;
use super::fixtures::audience;
use super::fixtures::authority_key;
use super::fixtures::authority_resolver;
use super::fixtures::root_key;
use super::fixtures::ADMISSION_REFUSED;
use super::fixtures::NOW;
use super::fixtures::ROOT_KID;
use super::fixtures::VERIFIER_AUD;
use super::wire::block_on;
use super::wire::served_of;
use super::wire::signed_call;
use super::wire::wire_code_of;

const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const TTL: i64 = 300;

/// The default enforcing policy: no degraded mode, so an unreachable authority is a
/// refusal rather than a judgement call.
pub(super) fn strict_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        max_assertion_age: 600,
        max_clock_skew: 30,
        degraded_propagation_bound: 0,
        allow_degraded_mode: false,
    }
}

/// The strict policy with a BOUNDED degraded window of `bound` seconds switched on.
pub(super) fn degraded_policy(bound: i64) -> AdmissionPolicy {
    AdmissionPolicy {
        allow_degraded_mode: true,
        degraded_propagation_bound: bound,
        ..strict_policy()
    }
}

/// A policy that refuses everything, installed to measure ONE proposition.
pub(super) struct RefusesEverything;

impl mcp_re_proxy::authorization::AuthorizationEvaluator for RefusesEverything {
    fn evaluate(
        &self,
        _: &mcp_re_proxy::authorization::AuthorizationRequest,
    ) -> Result<mcp_re_proxy::authorization::AuthorizedDecision, mcp_re_policy::PolicyError> {
        Err(mcp_re_policy::PolicyError::AuthorizationScopeDenied)
    }
}

/// An inner that COUNTS the calls that reached it. The count is the assertion that
/// matters for a currency check: a rejection issued after the tool ran is a record of
/// something that already happened.
fn counting_inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
    Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
        move |_forwarded: &[u8]| -> Vec<u8> {
            calls.fetch_add(1, Ordering::SeqCst);
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
        },
        mcp_re_proxy::async_inner::DispatchCompletionBound::Within(std::time::Duration::ZERO),
    ))
}

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: VERIFIER_AUD.into(),
        audience_hash: AUD_SCOPE.into(),
        trust_epoch: EPOCH.parse().expect("epoch base"),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        window: DelegatedKeyWindow::of(TTL, 60).expect("0 < overlap < ttl"),
    }
}

fn ready_signer() -> Arc<DelegatedServerSigner> {
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut rotor = DelegatedRotor::new(DelegatedSigningCustody::new(
        custody_cfg(),
        root_key().public_key(),
        issue,
        factory,
    ));
    let signer = rotor.signer();
    rotor.rotate(NOW).expect("issue first delegated key");
    std::mem::forget(rotor);
    signer
}

/// One fleet replica: its own signer and replay tier, consulting a source for admission.
/// Replicas share the SOURCE and nothing else, which is what makes a cross-replica
/// revocation claim meaningful.
pub(super) struct Rig {
    proxy: HttpProfileProxy,
    calls: Arc<AtomicUsize>,
}

impl Rig {
    pub(super) fn new(
        source: Arc<dyn AsyncAdmissionSource>,
        policy: AdmissionPolicy,
        enforcement: AdmissionEnforcement,
    ) -> Rig {
        let calls = Arc::new(AtomicUsize::new(0));
        let proxy = HttpProfileProxy::new_delegated(
            actor_resolver(),
            audience(),
            ReplayAdmission::new(
                AsyncReplayTier::new(
                    Arc::new(InMemoryAsyncAtomicReplayStore::new()),
                    mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
                ),
                ReplayPosture::SingleProcess,
            ),
            counting_inner(Arc::clone(&calls)),
            300,
            ready_signer(),
        )
        .with_admission(source, policy, enforcement, authority_resolver());
        Rig { proxy, calls }
    }

    /// A replica that REQUIRES admission under the strict policy.
    pub(super) fn strict(source: Arc<dyn AsyncAdmissionSource>) -> Rig {
        Rig::new(source, strict_policy(), AdmissionEnforcement::Required)
    }

    /// A degraded-mode deployment that has ALREADY earned its window — the configuration in
    /// which a misclassified refusal would actually serve a revoked workload.
    ///
    /// The window is opened first with a live-confirmed call, so nothing measured through the
    /// returned replica passes merely because degraded mode was unreachable.
    pub(super) fn with_an_open_degraded_window(source: &Arc<InMemoryAdmissionSource>) -> Rig {
        let rig = Rig::new(
            Arc::clone(source) as Arc<dyn AsyncAdmissionSource>,
            degraded_policy(120),
            AdmissionEnforcement::Required,
        );
        let served = rig.confirm_live();
        assert_eq!(served.status, 200, "the degraded window must start OPEN");
        rig
    }

    /// Records every request outcome this replica reaches into the returned sink.
    pub(super) fn audited(self) -> (Rig, Arc<CollectingAuditSink>) {
        let sink = Arc::new(CollectingAuditSink::new());
        let proxy = self.proxy.with_audit_sink(sink.clone());
        (
            Rig {
                proxy,
                calls: self.calls,
            },
            sink,
        )
    }

    /// Installs an authorization evaluator on the replica.
    pub(super) fn authorizing(
        self,
        evaluator: Arc<dyn mcp_re_proxy::authorization::AuthorizationEvaluator>,
    ) -> Rig {
        Rig {
            proxy: self.proxy.with_authorization(evaluator),
            calls: self.calls,
        }
    }

    /// The number of calls that reached the backend.
    pub(super) fn backend_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(super) fn serve(&self, req: &HttpRequest, now: i64) -> ServedHttpResponse {
        block_on(self.proxy.handle(served_of(req), now))
    }

    /// A call presenting `claims`, the assertion signed by `signer`, at a fresh nonce.
    pub(super) fn serve_signed_by(
        &self,
        claims: &AdmissionClaims,
        signer: &SigningKey,
        now: i64,
    ) -> ServedHttpResponse {
        self.serve(
            &signed_call(Some((claims, signer)), &unique_test_nonce()),
            now,
        )
    }

    /// A call presenting `claims`, the assertion signed by the real admission authority.
    pub(super) fn serve_claims(&self, claims: &AdmissionClaims, now: i64) -> ServedHttpResponse {
        self.serve_signed_by(claims, &authority_key(), now)
    }

    /// A call that declares no admission at all.
    pub(super) fn serve_bare(&self, now: i64) -> ServedHttpResponse {
        self.serve(&signed_call(None, &unique_test_nonce()), now)
    }

    /// A call whose assertion was issued thirty seconds before the fixture clock — the shape
    /// of a call made while the authority was reachable, which is what opens a degraded window.
    pub(super) fn confirm_live(&self) -> ServedHttpResponse {
        let confirmed = admission_claims(5, AdmissionStatus::Admitted, NOW - 30);
        self.serve_claims(&confirmed, NOW)
    }

    /// The call was refused as an admission failure, and `backend_calls` calls ran before it.
    pub(super) fn assert_refused(
        &self,
        served: &ServedHttpResponse,
        backend_calls: usize,
        why: &str,
    ) {
        assert_eq!(served.status, 403);
        assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
        assert_eq!(self.backend_calls(), backend_calls, "{why}");
    }
}

/// The admission facets recorded on the audit records of `event_type`.
pub(super) fn recorded_facets(sink: &CollectingAuditSink, event_type: &str) -> Vec<AdmissionFacet> {
    sink.records()
        .iter()
        .filter(|r| r.event().event_type() == event_type)
        .filter_map(|r| r.subject.admission())
        .collect()
}

/// The refusal classes a replica's audit sink recorded for the request records it refused.
pub(super) fn recorded_refusal_classes(
    sink: &CollectingAuditSink,
) -> Vec<Option<AdmissionRefusalClass>> {
    sink.records()
        .iter()
        .filter(|r| r.event().event_type() == "mcp-re.request.rejected")
        .map(|r| r.subject.admission_refusal())
        .collect()
}
