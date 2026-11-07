//! The signed-request and delegated-PEP fixtures of the full serving path.

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::{ReplayAdmission, ReplayPosture};
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const VERIFIER_AUD: &str = "verifier-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// The serving clock. A LIVE replay store derives each key's TTL from the
/// REAL wall clock, so a frozen fixture timestamp would make every insert
/// look long-expired and admit nothing — these lanes run on real time and
/// read it ONCE per test so the whole race shares one `now`.
pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// The client key resolves for the Request slot and the ROOT key for the
/// Response slot — the delegated key is authorized by its credential.
fn actor_resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key().public_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key().public_key()),
            _ => return ResolverOutcome::NotTrusted,
        };
        ResolverOutcome::Resolved(Box::new(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        }))
    })
}

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: VERIFIER_AUD.into(),
        audience_hash: VERIFIER_AUD.into(),
        trust_epoch: "epoch-1".parse().expect("epoch base"),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        window: DelegatedKeyWindow::of(300, 60).expect("0 < overlap < ttl"),
    }
}

/// A delegated-signing PEP over `store` as its authoritative async replay
/// tier, with its first delegated key already published. `seed_base`
/// distinguishes the delegated key material of independent replicas.
pub(super) fn proxy_over(
    store: Arc<dyn AsyncAtomicReplayStore>,
    seed_base: u8,
    now: i64,
) -> HttpProfileProxy {
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = seed_base;
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
    rotor.rotate(now).expect("issue the first delegated key");
    let inner = Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
        |_forwarded: &[u8]| -> Vec<u8> {
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
        },
        mcp_re_proxy::async_inner::DispatchCompletionBound::Within(std::time::Duration::ZERO),
    ));
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        ReplayAdmission::new(
            AsyncReplayTier::new(
                store,
                mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
            ),
            ReplayPosture::SingleProcess,
        ),
        inner,
        300,
        signer,
    )
}

/// A client-signed RFC 9421 + RFC 9530 request carrying `nonce`.
pub(super) fn signed_request(nonce: &str, now: i64) -> HttpRequest {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KEY_ID,
        now - 60,
        now + 240,
        nonce,
    )
    .expect("client signs the RFC 9421 request");
    req
}

pub(super) fn served(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        peer: None,
        assertion: None,
    }
}
