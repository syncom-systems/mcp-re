// SPDX-License-Identifier: Apache-2.0
//! Keys, frozen instants, the trust seam and the signed request every vector starts from.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const DELEGATED_SEED: [u8; 32] = [44u8; 32];
const DELEGATED2_SEED: [u8; 32] = [45u8; 32];
const ATTACKER_SEED: [u8; 32] = [99u8; 32];

pub(super) const CREATED: i64 = 1_700_000_000;
pub(super) const EXPIRES: i64 = 1_700_000_300;
/// The frozen verification instant every runner uses.
pub(super) const NOW: i64 = 1_700_000_100;

const CLIENT_KID: &str = "client-key-1";
pub(super) const ROOT_KID: &str = "root-kid";
pub(super) const DELEGATED_KID: &str = "root-kid/delegated/1";
pub(super) const DELEGATED2_KID: &str = "root-kid/delegated/2";
pub(super) const VERIFIER_AUD: &str = "verifier-1";
pub(super) const AUD_SCOPE: &str = "aud-scope-1";
pub(super) const EPOCH: &str = "epoch-1";
pub(super) const NEXT_EPOCH: &str = "epoch-2";

const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
pub(super) fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
pub(super) fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}
pub(super) fn delegated2_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED2_SEED)
}
pub(super) fn attacker_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ATTACKER_SEED)
}

/// Slot-aware trust seam: the client key for the Request slot, the ROOT key (by
/// its `issuer_kid`) for the Response slot. The DELEGATED keys are never enrolled
/// here — they are authorized by the credential chain alone.
pub(super) fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KID, SignerSlot::Request) => ("client", client_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

/// A server-signer identity whose `keyid` IS the given delegated-key id.
pub(super) fn server_signer_for(delegated_kid: &str) -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: delegated_kid.into(),
    }
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

pub(super) fn response_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
}

pub(super) fn signed_request() -> (HttpRequest, RequestRoleEvidence) {
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
    let ev = sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KID,
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("sign request");
    (req, ev)
}

pub(super) fn recompute_verified_request(req: &HttpRequest) -> VerifiedMcpRequest {
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(req, &audience(), &no_material(), NOW)
        .expect("frozen request re-verifies")
}
