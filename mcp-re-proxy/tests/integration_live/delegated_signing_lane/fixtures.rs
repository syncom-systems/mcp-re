// SPDX-License-Identifier: Apache-2.0
#![cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
//! The client, request and response the delegated-signing custody lane signs and verifies.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
pub(super) const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

pub(super) const VERIFIER_AUD: &str = "verifier-1";
pub(super) const AUD_SCOPE: &str = "aud-scope-1";
pub(super) const EPOCH: &str = "epoch-1";

// Custody policy: delegated-key TTL `T` and rotation-overlap window `O` (0 < O < T).
pub(super) const TTL: i64 = 300;
pub(super) const OVERLAP: i64 = 60;

pub(super) fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
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

fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

/// The request-leg verify only needs the client key; the response root is resolved
/// later against the concrete KMS public key.
fn resolver_client_only() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        ("client-key-1", SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: "client-key-1".into(),
            },
            verification_key: client_pub.clone(),
            slot,
        }),
        _ => None,
    }
}

/// A signed request the verifier admits.
pub(super) fn signed_request() -> HttpRequest {
    let mut req = base_request();
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
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        &RequestSignature {
            key_id: "client-key-1",
            created: CREATED,
            expires: EXPIRES,
            nonce: &mcp_re_test_paths::unique_test_nonce(),
        },
    )
    .expect("sign request");
    Verifier::new(&VerifierPolicy::default(), &resolver_client_only())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("verify request");
    req
}

pub(super) fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

pub(super) fn fresh_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}
