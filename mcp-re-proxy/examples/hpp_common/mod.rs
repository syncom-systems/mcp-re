// SPDX-License-Identifier: Apache-2.0
//! Shared demo material for the HTTP-profile proof pair (`http_profile_proxy`
//! server + `http_profile_client` driver). NOT a standalone example — it lives in
//! a subdirectory so it is not built as its own binary; each example
//! pulls it in with `#[path = "hpp_common/mod.rs"] mod hpp_common;`.
//!
//! The identities/keys are DETERMINISTIC demo seeds (same pattern as
//! `tests/http_profile_dispatch_test.rs`) so client and server agree without a
//! shared key file. Addresses/target come from the environment — the launcher
//! resolves them from `config/ports.toml`, so no port literal is baked in here.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

/// Demo client request-signing seed (Ed25519). Deterministic — proof material.
pub const CLIENT_SEED: [u8; 32] = [11u8; 32];
/// Demo server response-signing seed (Ed25519). Deterministic — proof material.
///
/// This is the ROOT / trust-anchor key. It signs the delegation credential and is the
/// only key a client enrols; it never signs a response itself (ADR-MCPRE-052).
pub const SERVER_SEED: [u8; 32] = [22u8; 32];
/// Demo DELEGATED response-signing seed. Authorized by the credential the root signs,
/// and never enrolled by the verifier — that is the whole point of delegation.
pub const DELEGATED_SEED: [u8; 32] = [44u8; 32];
pub const CLIENT_KEY_ID: &str = "client-key-1";
/// The root/issuer kid. Named `SERVER_KEY_ID` for continuity with the client driver.
pub const SERVER_KEY_ID: &str = "server-key-1";
pub const TRUST_DOMAIN: &str = "example.com";
pub const CLIENT_SUBJECT: &str = "did:example:host-a";
pub const SERVER_SUBJECT: &str = "did:example:server-1";
pub const AUDIENCE_ID: &str = "verifier-1";
pub const ROUTE: &str = "a";
/// The credential's audience-scope claim, checked against the verifier's policy.
pub const AUD_SCOPE: &str = "aud-scope-1";
/// The trust epoch the credential is minted under; a verifier gates on it.
pub const EPOCH: &str = "epoch-1";
/// How long a minted credential stays valid, in seconds.
pub const CREDENTIAL_TTL: i64 = 3600;
/// How long a signed response advertises validity for, in seconds.
pub const RESPONSE_TTL: i64 = 300;
/// Demo access token bound by the request's OAuth DPoP artifact binding. The
/// evidence block requires at least one artifact binding; DPoP derives its
/// credential from the covered `Authorization: Bearer` header.
pub const ACCESS_TOKEN: &str = "access-token-xyz";

pub fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
/// The ROOT / trust-anchor key. It signs the delegation credential — never a response.
pub fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}
/// The DELEGATED key that actually signs responses, authorized by the credential.
pub fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}

pub fn client_identity() -> ActorIdentity {
    ActorIdentity {
        role: "client".into(),
        trust_domain: TRUST_DOMAIN.into(),
        subject: CLIENT_SUBJECT.into(),
        keyid: CLIENT_KEY_ID.into(),
    }
}

/// The root/issuer identity: the anchor a verifier enrols and the credential chains to.
pub fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: TRUST_DOMAIN.into(),
        subject: SERVER_SUBJECT.into(),
        keyid: SERVER_KEY_ID.into(),
    }
}

type Issue = Box<dyn FnMut(&DelegationHeader, &DelegationClaims) -> Option<String> + Send>;
type Factory = Box<dyn FnMut() -> SigningKey + Send>;

/// The demo's delegated-signing custody: the ROOT (`server_key`) issues the credential the
/// delegated key presents (ADR-MCPRE-052), and rotates it, through the same
/// `DelegatedSigningCustody` the shipped serving path runs. The root attests that the
/// delegated key may sign responses for this verifier, profile, audience scope and trust
/// epoch.
///
/// This is the ISSUER side, kept here so the proof pair runs self-contained. In production
/// the root is a KMS/HSM anchor, not a seed in the serving process.
fn custody() -> &'static Mutex<DelegatedSigningCustody<Issue, Factory>> {
    static CUSTODY: OnceLock<Mutex<DelegatedSigningCustody<Issue, Factory>>> = OnceLock::new();
    CUSTODY.get_or_init(|| {
        let cfg = CustodyConfig {
            issuer_kid: SERVER_KEY_ID.into(),
            iss: SERVER_SUBJECT.into(),
            profile: PROFILE_TAG.into(),
            aud: AUDIENCE_ID.into(),
            audience_hash: AUD_SCOPE.into(),
            trust_epoch: EPOCH.parse().expect("EPOCH is a trust epoch"),
            server_role: "server".into(),
            server_trust_domain: TRUST_DOMAIN.into(),
            server_subject: SERVER_SUBJECT.into(),
            window: DelegatedKeyWindow::of(CREDENTIAL_TTL, CREDENTIAL_TTL / 6)
                .expect("0 < overlap < ttl"),
        };
        let root = server_key();
        let issue: Issue = Box::new(move |h, c| Some(issue_delegation_credential(&root, h, c)));
        let factory: Factory = Box::new(delegated_key);
        Mutex::new(DelegatedSigningCustody::new(
            cfg,
            server_key().public_key(),
            issue,
            factory,
        ))
    })
}

/// The window a response is signed under at `now`: the custody's active delegated key,
/// rotated if due, advertising `RESPONSE_TTL` seconds or the credential's own expiry,
/// whichever closes first.
pub fn signing_window(now: i64) -> SigningWindow {
    let mut custody = custody().lock().expect("custody lock");
    custody.ensure_active(now).expect("the demo root issues");
    let active = custody.active_snapshot().expect("an issuance is active");
    SigningWindow::over(Arc::new(active), now, RESPONSE_TTL)
        .expect("an active credential opens a window")
}

/// The canonical `@target-uri` (RFC 9421) both sides use verbatim, from
/// `HPP_TARGET` (launcher-supplied, registry-derived). Signing covers this string,
/// so client and server MUST agree on it byte-for-byte.
pub fn target() -> String {
    std::env::var("HPP_TARGET").expect("HPP_TARGET must be set (e.g. http://127.0.0.1:8601/mcp)")
}

/// The verifier's audience tuple. `target_uri` must equal the request
/// `@target-uri` (verify_request_full enforces it).
pub fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUDIENCE_ID.into(),
        target_uri: target(),
        route: Some(ROUTE.into()),
    }
}

/// The trust seam: the client key is trusted ONLY for the Request slot, the server
/// key ONLY for the Response slot (MCPRE-100 slot discipline). A key presented on
/// the wrong slot resolves to `None` → `actor_binding_failed`.
pub fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: client_identity(),
            verification_key: client_key().public_key(),
            slot,
        }),
        (SERVER_KEY_ID, SignerSlot::Response) => Some(ResolvedActor {
            identity: server_identity(),
            verification_key: server_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}
