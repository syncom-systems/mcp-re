// SPDX-License-Identifier: Apache-2.0
//! The requests, resolver, configuration and canned responses both lanes are built from.

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::async_serve::ServedHttpResponse;

use super::Lane;

pub(super) const NOW: i64 = 1_700_000_100;
pub(super) const VERIFIER_AUD: &str = "verifier-1";
pub(super) const EPOCH: &str = "epoch-1";
pub(super) const NEW_EPOCH: &str = "epoch-2";
pub(super) const TTL: i64 = 300;
pub(super) const OVERLAP: i64 = 60;
// A batch comfortably larger than 1, to prove the KMS is not touched per request.
pub(super) const RESPONSES_PER_KEY: usize = 8;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";

/// The instant after which a predecessor key is inside its overlap with its successor.
pub(super) fn overlap_instant() -> i64 {
    NOW + TTL - OVERLAP + 10
}

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

pub(super) fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

impl Lane {
    /// Resolver: the client key for the Request slot, the KMS ROOT public key (by its
    /// issuer kid) for the Response slot. The DELEGATED key is never enrolled; the
    /// KMS-signed credential authorizes it.
    pub(super) fn resolver(
        &self,
        root_pub: VerificationKey,
    ) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync + Clone {
        let client_pub = client_key().public_key();
        let root_kid = self.root_kid;
        move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_pub.clone()),
                (kid, SignerSlot::Response) if kid == root_kid => ("server", root_pub.clone()),
                _ => return None,
            };
            Some(ResolvedActor {
                identity: ActorIdentity {
                    role: role.into(),
                    trust_domain: "mcp.example.com".into(),
                    subject: format!("did:example:{role}"),
                    keyid: key_id.into(),
                },
                verification_key: key,
                slot,
            })
        }
    }

    pub(super) fn custody_cfg(&self) -> CustodyConfig {
        CustodyConfig {
            issuer_kid: self.root_kid.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: VERIFIER_AUD.into(),
            audience_hash: VERIFIER_AUD.into(),
            trust_epoch: EPOCH.parse().expect("epoch base"),
            server_role: "server".into(),
            server_trust_domain: "mcp.example.com".into(),
            server_subject: "did:example:server".into(),
            window: DelegatedKeyWindow::of(TTL, OVERLAP).expect("0 < overlap < ttl"),
        }
    }

    /// The production serving DeploymentRequest in delegated-required mode (parser-produced,
    /// as the binary does). Filesystem paths are placeholders — the delegated wiring reads
    /// config fields, not files. `--server-key-id` becomes the credential issuer kid.
    pub(super) fn delegated_config(&self) -> mcp_re_proxy::deployment_request::DeploymentRequest {
        let args: Vec<String> = [
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            VERIFIER_AUD,
            "--allow-example-fixtures",
            "--server-signer",
            "did:example:server",
            "--server-key-id",
            self.root_kid,
            "--signing-key-seed",
            "/dev/null",
            "--tls-cert",
            "/dev/null",
            "--tls-key",
            "/dev/null",
            "--client-ca",
            "/dev/null",
            "--trust",
            "/dev/null",
            "--inner-http-url",
            "http://127.0.0.1:9",
            "--target-uri",
            TARGET,
            "--mcp-protocol-version",
            "2026-07-28",
            "--route",
            "a",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
            "--delegated-trust-epoch",
            EPOCH,
            "--trust-domain",
            "mcp.example.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        mcp_re_proxy::cli::parse_args(&args)
            .expect("parse delegated-required serving config")
            .config()
            .clone()
    }
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

/// A client-signed request whose freshness window brackets the serve instant `at` (so
/// serving at `at` exercises the SIGNING step, not a freshness rejection), verified at `at`
/// for the response binding. `nonce` distinguishes replays.
pub(super) fn signed_request(nonce: &str, at: i64) -> HttpRequest {
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
    let mut req = base_request();
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: at - 100,
            expires: at + 200,
            nonce,
        },
    )
    .expect("client signs RFC 9421 request");
    let no_material = |_b: &ArtifactBinding| None;
    let r = resolver_client_only();
    Verifier::new(&VerifierPolicy::default(), &r)
        .verify_request(&req, &audience(), &no_material, at)
        .expect("client's own request verifies (for response binding)");
    req
}

/// Request-leg resolver (client key only); the response root is resolved separately
/// against the concrete KMS public key.
fn resolver_client_only() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: CLIENT_KEY_ID.into(),
            },
            verification_key: client_pub.clone(),
            slot,
        }),
        _ => None,
    }
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

pub(super) fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
        |_forwarded: &[u8]| -> Vec<u8> {
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
        },
        mcp_re_proxy::async_inner::DispatchCompletionBound::Within(std::time::Duration::ZERO),
    ))
}

pub(super) fn fresh_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

/// The `SigningPlan` `app::run` projects, so a lane drives the production wiring through the
/// same plan the binary does — including the boundary that produces it.
pub(super) fn signing_plan(
    config: &mcp_re_proxy::deployment_request::DeploymentRequest,
) -> mcp_re_proxy::startup_plan::SigningPlan {
    let validated =
        mcp_re_proxy::config_state::validation::ValidatedDeployment::try_from(config.clone())
            .expect("the fixture config must validate");
    mcp_re_proxy::startup_plan::response_authority_plans(&validated).1
}
