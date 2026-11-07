// SPDX-License-Identifier: Apache-2.0
//! Keys, trust, custody and signing shared by every serving test, and the one place a
//! serving proxy is assembled.

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
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidenceDigest;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_dispatch::ReplayAdmission;
use mcp_re_proxy::http_profile_dispatch::ReplayPosture;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_proxy::SigningRetirement;

pub(super) const CLIENT_SEED: [u8; 32] = [11u8; 32];
const CLIENT_SEED_2: [u8; 32] = [12u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
pub(super) const NOW: i64 = 1_700_000_100;
pub(super) const CREATED: i64 = 1_700_000_000;
pub(super) const EXPIRES: i64 = 1_700_000_300;
pub(super) const TARGET: &str = "https://mcp.example.com/mcp?route=a";
pub(super) const ACCESS_TOKEN: &str = "access-token-xyz";
pub(super) const CLIENT_KEY_ID: &str = "client-key-1";
const CLIENT_KEY_ID_2: &str = "client-key-2";
pub(super) const ROOT_KID: &str = "root-kid";
pub(super) const VERIFIER_AUD: &str = "verifier-1";
pub(super) const AUD_SCOPE: &str = "aud-scope-1";
pub(super) const EPOCH: &str = "epoch-1";
pub(super) const TTL: i64 = 300;
const OVERLAP: i64 = 60;

/// The default response-signature lifetime a serving proxy is configured with.
pub(super) const RESPONSE_SIG_TTL: i64 = 300;

pub(super) const OPEN_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"confirm_action","arguments":{}}}"#;

/// A client the resolver trusts for the Request slot.
pub(super) struct Actor {
    pub(super) key_id: &'static str,
    pub(super) key: SigningKey,
}

pub(super) fn first_actor() -> Actor {
    Actor {
        key_id: CLIENT_KEY_ID,
        key: SigningKey::from_seed_bytes(&CLIENT_SEED),
    }
}

/// A SECOND legitimate client: a distinct actor the resolver trusts for the Request
/// slot, so "verified" and "the actor that opened the leg" can be told apart.
pub(super) fn second_actor() -> Actor {
    Actor {
        key_id: CLIENT_KEY_ID_2,
        key: SigningKey::from_seed_bytes(&CLIENT_SEED_2),
    }
}

pub(super) fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}

pub(super) fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

pub(super) fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync + Clone
{
    move |key_id: &str, slot: SignerSlot| {
        let (role, subject, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => (
                "client",
                "did:example:host-a",
                first_actor().key.public_key(),
            ),
            // A second trusted client — same role, different subject and keyid, so it
            // resolves to a DIFFERENT actor id.
            (CLIENT_KEY_ID_2, SignerSlot::Request) => (
                "client",
                "did:example:host-b",
                second_actor().key.public_key(),
            ),
            (ROOT_KID, SignerSlot::Response) => {
                ("server", "did:example:server", root_key().public_key())
            }
            _ => return None,
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
    }
}

fn actor_resolver() -> ActorResolver {
    let r = resolver();
    Box::new(move |kid: &str, slot: SignerSlot| r(kid, slot).into())
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
        window: DelegatedKeyWindow::of(TTL, OVERLAP).expect("0 < overlap < ttl"),
    }
}

/// A rotor over `cfg` whose delegated keys are seeded from `first_seed` upward.
fn rotor_over(
    cfg: CustodyConfig,
    first_seed: u8,
) -> DelegatedRotor<
    impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    impl FnMut() -> SigningKey,
> {
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = first_seed;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    DelegatedRotor::new(DelegatedSigningCustody::new(
        cfg,
        root_key().public_key(),
        issue,
        factory,
    ))
}

/// Drive `rotor_over(cfg, first_seed)` once and keep it alive for the whole test, so the
/// published snapshot stays valid; return the signer and the authority to withdraw it.
fn published(
    cfg: CustodyConfig,
    first_seed: u8,
) -> (Arc<DelegatedServerSigner>, SigningRetirement) {
    let mut rotor = rotor_over(cfg, first_seed);
    let signer = rotor.signer();
    let retirement = rotor.retirement();
    rotor.rotate(NOW).expect("issue first delegated key");
    std::mem::forget(rotor);
    (signer, retirement)
}

pub(super) fn ready_signer() -> Arc<DelegatedServerSigner> {
    ready_signer_and_retirement().0
}

/// A ready signer, and the authority its rotor issues to withdraw it for good.
pub(super) fn ready_signer_and_retirement() -> (Arc<DelegatedServerSigner>, SigningRetirement) {
    published(custody_cfg(), 100)
}

/// A delegated signer whose credential expires in `ttl` seconds rather than [`TTL`].
///
/// The overlap must sit strictly inside the TTL: an `overlap >= ttl` pair makes every
/// instant "due for rotation" and puts the root on the per-request path. Half the life is
/// strictly inside any `ttl > 1`, and the rotor here is driven exactly once, so the
/// rotation threshold this picks is never consulted by these tests.
pub(super) fn signer_with_credential_ttl(ttl: i64) -> Arc<DelegatedServerSigner> {
    let cfg = CustodyConfig {
        window: DelegatedKeyWindow::of(ttl, ttl / 2).expect("0 < ttl/2 < ttl for ttl > 1"),
        ..custody_cfg()
    };
    published(cfg, 200).0
}

/// A serving proxy over `inner`, signing with `signer` and advertising `response_ttl`,
/// with a fresh replay tier and no continuation store, retention or transport binding.
pub(super) fn bare_proxy(
    inner: Box<dyn AsyncInnerServer>,
    signer: Arc<DelegatedServerSigner>,
    response_ttl: i64,
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
        inner,
        response_ttl,
        signer,
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

pub(super) fn http_response(served: ServedHttpResponse) -> HttpResponse {
    HttpResponse {
        status: served.status,
        headers: served.headers,
        body: served.body,
    }
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

/// Sign an RFC 9421 request as the default client.
pub(super) fn signed_request(
    nonce: &str,
    body: &[u8],
    continuation: Option<HttpContinuation>,
) -> (HttpRequest, RequestRoleEvidence) {
    signed_request_as(&first_actor(), nonce, body, continuation)
}

/// Sign an RFC 9421 request AS a named actor, with an optional MRTR continuation in
/// the evidence block.
pub(super) fn signed_request_as(
    actor: &Actor,
    nonce: &str,
    body: &[u8],
    continuation: Option<HttpContinuation>,
) -> (HttpRequest, RequestRoleEvidence) {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation,
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
        body: body.to_vec(),
    };
    let evidence = sign_request_full(
        &mut req,
        &block,
        &actor.key,
        &RequestSignature {
            key_id: actor.key_id,
            created: CREATED,
            expires: EXPIRES,
            nonce,
        },
    )
    .expect("client signs RFC 9421 request");
    (req, evidence)
}

/// The client verifies its own request, as it would before keeping it for response binding.
pub(super) fn verify_request(request: &HttpRequest) {
    let resolve = resolver();
    let policy = VerifierPolicy::default();
    let no_material = |_b: &ArtifactBinding| None;
    Verifier::new(&policy, &resolve)
        .verify_request(request, &audience(), &no_material, NOW)
        .expect("the client's own request verifies");
}

/// The client verifies the delegated reply bound to `request`, and reads the evidence
/// handle its signature base gives (the `D_irr` of the next leg's continuation).
pub(super) fn verified_reply_handle(
    reply: &HttpResponse,
    request: &HttpRequest,
) -> RequestEvidenceDigest {
    let resolve = resolver();
    let policy = VerifierPolicy::default();
    Verifier::new(&policy, &resolve)
        .verify_delegated_bound_response(reply, request, &expectations(&[EPOCH]), &|_| false, NOW)
        .expect("the delegated reply verifies")
        .signature_facts()
        .response_signature_base_digest
        .to_digest()
}
