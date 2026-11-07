// SPDX-License-Identifier: Apache-2.0
//! Keys, identities, requests and credentials shared by the delegated-signing battery.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_test_paths::unique_test_nonce;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const DELEGATED_SEED: [u8; 32] = [44u8; 32];
pub const NOW: i64 = 1_700_000_100;
pub const CREATED: i64 = 1_700_000_000;
pub const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KID: &str = "client-key-1";

pub const ROOT_KID: &str = "root-kid";
pub const DELEGATED_KID: &str = "root-kid/delegated/1";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
pub const EPOCH: &str = "epoch-1";

pub fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
pub fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
pub fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}

/// A key no credential confirms, seeded by `seed`.
pub fn attacker_key(seed: u8) -> SigningKey {
    SigningKey::from_seed_bytes(&[seed; 32])
}

/// An `example.com` actor of `role` signing under `keyid`.
pub fn identity(role: &str, keyid: &str) -> ActorIdentity {
    ActorIdentity {
        role: role.into(),
        trust_domain: "example.com".into(),
        subject: format!("did:example:{role}"),
        keyid: keyid.into(),
    }
}

fn resolved(role: &str, keyid: &str, key: &SigningKey, slot: SignerSlot) -> ResolvedActor {
    ResolvedActor {
        identity: identity(role, keyid),
        verification_key: key.public_key(),
        slot,
    }
}

/// Resolver: the client key for the Request slot, and the ROOT key (by its
/// `issuer_kid`) for the Response slot — the credential's issuer is resolved for
/// the Response slot. The DELEGATED key is never enrolled here; it is authorized
/// by the credential alone.
pub fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KID, SignerSlot::Request) => Some(resolved("client", key_id, &client_key(), slot)),
        (ROOT_KID, SignerSlot::Response) => Some(resolved("server", key_id, &root_key(), slot)),
        _ => None,
    }
}

/// A seam that knows the client but has never heard of the root.
pub fn seam_without_the_root() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KID, SignerSlot::Request) => Some(resolved("client", key_id, &client_key(), slot)),
        _ => None,
    }
}

/// The delegated server-signer identity — its `keyid` IS the delegated key id.
pub fn server_signer() -> ActorIdentity {
    identity("server", DELEGATED_KID)
}

/// The root server identity, as a directly root-signed response names it.
pub fn root_signer() -> ActorIdentity {
    identity("server", ROOT_KID)
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

/// No caller-supplied artifact material — DPoP `ath` is header-derived.
fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

/// A freshly signed request and its evidence handle; every call is a distinct exchange.
pub fn sign_a_request() -> (HttpRequest, RequestRoleEvidence) {
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
    let evidence = sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KID,
        CREATED,
        EXPIRES,
        &unique_test_nonce(),
    )
    .expect("sign request");
    (req, evidence)
}

/// A signed request, its evidence, and the verifier's view of it.
pub fn signed_request() -> (HttpRequest, RequestRoleEvidence, VerifiedMcpRequest) {
    let (req, evidence) = sign_a_request();
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("verify request");
    (req, evidence, verified)
}

fn delegation_header() -> DelegationHeader {
    DelegationHeader {
        typ: DELEGATION_TYP.into(),
        alg: DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    }
}

fn delegation_claims(subject: &ActorIdentity, jti: &str) -> DelegationClaims {
    DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: jti.into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: subject.actor_id(),
        mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: DELEGATED_KID.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: JWK_KTY_OKP.into(),
                crv: JWK_CRV_ED25519.into(),
                kid: DELEGATED_KID.into(),
                x: delegated_key().public_key().to_b64url(),
            },
        },
    }
}

/// Mint a valid delegation credential (root-signed) binding the delegated key.
pub fn valid_credential() -> String {
    issue_delegation_credential(
        &root_key(),
        &delegation_header(),
        &delegation_claims(&server_signer(), "evt-1"),
    )
}

/// A credential whose SUBJECT BINDING and CONFIRMED KEY name different key ids.
///
/// `mcp_re_server_signer` scopes the credential to `disowned-kid`, so a block declaring
/// that signer passes the credential's scope check; `cnf.jwk`/`delegated_kid` confirm
/// `DELEGATED_KID`, and the response is signed by that key under that wire keyid. Every
/// other conjunct is satisfied — the chain verifies, the wire keyid equals the credential's
/// delegated kid, the signature verifies under `cnf.jwk` — so only the comparison of the
/// BLOCK's declared keyid against the credential's delegated kid refuses it.
///
/// Without it the product's accepted-signer identity would carry `disowned-kid` while the
/// signature verified under the key confirmed for `DELEGATED_KID`: the identity a consumer
/// attributes the response to would not be the identity the signature was accepted under,
/// which is exactly what the correspondence conjunct claims.
pub fn credential_scoped_to_another_keyid() -> (String, ActorIdentity) {
    let mut disowned = server_signer();
    disowned.keyid = "disowned-kid".into();
    let credential = issue_delegation_credential(
        &root_key(),
        &delegation_header(),
        &delegation_claims(&disowned, "evt-disowned"),
    );
    (credential, disowned)
}

pub fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

pub fn custody_cfg() -> CustodyConfig {
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

fn response_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
}

/// An unsigned JSON response with `status`.
pub fn json_response(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    }
}
