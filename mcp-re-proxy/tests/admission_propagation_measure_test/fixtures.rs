// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "redis_replay")]
//! The fixtures the propagation measurement runs on: the admission authority's keys and
//! signed records, the signed calls a client makes, and the replicas that serve them.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::authoritative_admission::record::issue_admission_state_record;
use mcp_re_http_profile::authoritative_admission::record::AdmissionStateClaims;
use mcp_re_http_profile::authoritative_admission::record::AdmissionStateCurrentness;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::issue_admission_assertion;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::admission_enforcer::AdmissionEnforcement;
use mcp_re_proxy::admission_source::AdmissionRecordVerifier;
use mcp_re_proxy::admission_source::AsyncAdmissionSource;
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::{ReplayAdmission, ReplayPosture};
use mcp_re_proxy::http_profile_serve::AdmissionAuthorityResolver;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

use sha2::Digest;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const AUTHORITY_SEED: [u8; 32] = [44u8; 32];
pub(super) const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const AUTHORITY_KID: &str = "admission-root-1";

pub(super) const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn authority_key() -> SigningKey {
    SigningKey::from_seed_bytes(&AUTHORITY_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// The actor id the PEP's verifier resolves for the signing client — the value an
/// assertion must name so it cannot be presented by anyone else.
fn test_actor() -> String {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:host-a".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id()
}

fn actor_resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        let (role, subject, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => {
                ("client", "did:example:host-a", client_key().public_key())
            }
            (ROOT_KID, SignerSlot::Response) => {
                ("server", "did:example:server", root_key().public_key())
            }
            _ => return None::<ResolvedActor>.into(),
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
        .into()
    })
}

fn authority_resolver() -> AdmissionAuthorityResolver {
    Arc::new(|kid: &str| (kid == AUTHORITY_KID).then(|| authority_key().public_key()))
}

/// The deployment's declared currentness budget for an authoritative record.
///
/// Wide relative to `DECLARED_P_MS`: this battery measures how fast a NEW publication
/// reaches a sibling replica, and a record expiring mid-poll would make it pass for the
/// wrong reason. The budget's own boundary is measured where it is decided.
const RECORD_MAX_AGE: i64 = 3_600;

/// A verifier that trusts exactly the admission authority, the one a real deployment
/// builds from its validated state.
pub(super) fn record_verifier() -> AdmissionRecordVerifier {
    AdmissionRecordVerifier::new(
        authority_resolver(),
        PROFILE_TAG,
        AdmissionStateCurrentness {
            max_record_age: RECORD_MAX_AGE,
            max_clock_skew: 30,
        },
    )
}

/// The AUTHORITY's signed statement about a workload.
///
/// Signing happens HERE, in the control-plane half of the harness, because that is where
/// it happens in a deployment: the serving replicas below hold a verifier and no key.
pub(super) fn signed_state(
    workload: &str,
    generation: u64,
    revision: u64,
    status: AdmissionStatus,
) -> String {
    issue_admission_state_record(
        &AdmissionStateClaims {
            iss: "did:example:admission".into(),
            iat: NOW,
            nbf: NOW,
            exp: NOW + RECORD_MAX_AGE,
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_admission_id: workload.into(),
            mcp_re_admission_generation: generation,
            mcp_re_admission_status: status,
            mcp_re_state_revision: revision,
            issuer_kid: AUTHORITY_KID.into(),
        },
        |input| {
            b64url_decode(&authority_key().sign(input))
                .map_err(|_| HttpProfileError::InvalidSignature)
        },
    )
    .expect("the authority issues its own record")
}

pub(super) fn admission_claims(workload: &str, generation: u64) -> AdmissionClaims {
    AdmissionClaims {
        iss: "did:example:admission".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: CREATED + 600,
        jti: format!("adm#{generation}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: workload.into(),
        mcp_re_admitted_actor: test_actor(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: b64url_encode(&sha2::Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: AdmissionStatus::Admitted,
        issuer_kid: AUTHORITY_KID.into(),
    }
}

/// A signed call under `claims`. The nonce must be fresh per call: the replay tier is
/// real, and a measurement loop that replayed one nonce would measure the replay
/// tier's refusal instead of the revocation's.
pub(super) fn signed_call(claims: &AdmissionClaims, nonce: &str) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    };
    let assertion = issue_admission_assertion(claims, |input| {
        b64url_decode(&authority_key().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue");
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: Some(AdmissionBinding::opaque_from(claims)),
        admission_assertion: Some(assertion),
        authorization_decision: None,
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce,
        },
    )
    .expect("signs");
    req
}

fn inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
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
        window: DelegatedKeyWindow::of(300, 60).expect("0 < overlap < ttl"),
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

/// One replica: its own signer, its own replay tier, its own connection to the shared
/// source. Nothing is shared but the store — which is what makes the propagation
/// claim about the store rather than about shared memory.
pub(super) fn replica(
    source: Arc<dyn AsyncAdmissionSource>,
    calls: Arc<AtomicUsize>,
) -> HttpProfileProxy {
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        ReplayAdmission::new(
            AsyncReplayTier::new(
                Arc::new(InMemoryAsyncAtomicReplayStore::new()),
                mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
            ),
            ReplayPosture::SingleProcess,
        ),
        inner(calls),
        300,
        ready_signer(),
    )
    .with_admission(
        source,
        AdmissionPolicy {
            max_assertion_age: 600,
            max_clock_skew: 30,
            // No degraded window: this measures propagation of a real revocation, and
            // a degraded fallback would let a store hiccup look like continued
            // admission and quietly inflate the measured delay.
            degraded_propagation_bound: 0,
            allow_degraded_mode: false,
        },
        AdmissionEnforcement::Required,
        authority_resolver(),
    )
}

pub(super) fn served_of(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        peer: None,
        assertion: None,
    }
}
