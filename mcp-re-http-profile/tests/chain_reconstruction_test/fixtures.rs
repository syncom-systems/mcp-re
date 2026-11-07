// SPDX-License-Identifier: Apache-2.0
//! Keys, delegation credential and verifier inputs shared by every chain in the battery.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::block::AudienceTuple;
use mcp_re_http_profile::custody::ActiveDelegatedKey;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

pub const CLIENT_SEED: [u8; 32] = [11u8; 32];
/// The ROOT issuer: the credential signer, off the request path. Delegated-required
/// is the only response-signing mode, so a reconstruction that could not verify a
/// delegated response could not verify any evidence the proxy actually emits.
pub const ROOT_SEED: [u8; 32] = [22u8; 32];
pub const DELEGATED_SEED: [u8; 32] = [44u8; 32];
pub const CREATED: i64 = 1_700_000_000;
pub const EXPIRES: i64 = 1_700_000_300;
pub const NOW: i64 = 1_700_000_100;
pub const CLIENT_KEY_ID: &str = "client-key-1";
pub const ROOT_KID: &str = "server-key-1";
pub const DELEGATED_KID: &str = "server-key-1/delegated/1";
pub const TARGET: &str = "https://mcp.example.com/mcp";
pub const VERIFIER_AUD: &str = "did:example:server";
pub const AUD_SCOPE: &str = "aud-scope-1";
pub const EPOCH: &str = "epoch-1";

pub const AWAITING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#;
pub const DONE: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

const REQUEST_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

pub fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
pub fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
pub fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}

/// The delegation credential every hop response carries inline. Minted over the
/// hop's own window so a chain whose turns sit at different times still verifies at
/// each hop's own instant.
pub fn credential(created: i64, expires: i64) -> String {
    let header = DelegationHeader {
        typ: mcp_re_http_profile::DELEGATION_TYP.into(),
        alg: mcp_re_http_profile::DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    };
    issue_delegation_credential(&root_key(), &header, &claims(created, expires))
}

fn claims(created: i64, expires: i64) -> DelegationClaims {
    DelegationClaims {
        iss: "did:example:server".into(),
        iat: created,
        nbf: created,
        exp: expires,
        jti: format!("evt-{created}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: server_signer().actor_id(),
        mcp_re_key_use: mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: DELEGATED_KID.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: mcp_re_http_profile::JWK_KTY_OKP.into(),
                crv: mcp_re_http_profile::JWK_CRV_ED25519.into(),
                kid: DELEGATED_KID.into(),
                x: delegated_key().public_key().to_b64url(),
            },
        },
    }
}

/// The delegated-verification inputs. Nothing is revoked in these chains; the
/// revocation seam is exercised by the delegation suite.
pub fn expectations() -> DelegationExpectations<'static> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: &[EPOCH],
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

pub fn nothing_revoked(_: &str) -> bool {
    false
}

pub fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            // The ROOT issuer, not the ephemeral delegated key: under
            // delegated-required the trust seam pins the root the credential chains
            // to, and the delegated key is authorized BY the credential rather than
            // enrolled.
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

pub fn audience() -> AudienceTuple {
    audience_named("mcp.example.com", TARGET)
}

/// An audience tuple on the one route the chains use, naming the given id and URI.
pub fn audience_named(audience_id: &str, target_uri: &str) -> AudienceTuple {
    AudienceTuple {
        audience_id: audience_id.into(),
        target_uri: target_uri.into(),
        route: Some("tools/call".into()),
    }
}

/// The full-profile audit inputs. The blocks under test carry an `OauthMtls` binding
/// over `b"tok"`, whose credential is caller material, so the material function is what
/// makes that binding checkable — a binding whose credential cannot be obtained fails closed.
fn artifact_material(_: &ArtifactBinding) -> Option<Vec<u8>> {
    Some(b"tok".to_vec())
}

static ARTIFACT_MATERIAL: fn(&ArtifactBinding) -> Option<Vec<u8>> = artifact_material;

pub fn audit() -> ChainAudit<'static> {
    static AUD: std::sync::OnceLock<AudienceTuple> = std::sync::OnceLock::new();
    ChainAudit {
        expected_audience: AUD.get_or_init(audience),
        artifact_material: &ARTIFACT_MATERIAL,
    }
}

pub fn server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: DELEGATED_KID.into(),
    }
}

pub fn block(continuation: Option<HttpContinuation>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthMtls,
            b"tok",
        )],
        continuation,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    }
}

/// The request every hop starts from, before any evidence is signed onto it.
pub fn unsigned_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: REQUEST_BODY.to_vec(),
    }
}

/// A 200 JSON response carrying `body`, before any signature is put on it.
pub fn unsigned_response(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

/// The delegated signing window over `[created, expires]`, under the credential minted
/// for exactly that window.
pub fn signing_window(created: i64, expires: i64) -> SigningWindow {
    SigningWindow::stated(
        ActiveDelegatedKey::stated(
            delegated_key(),
            server_signer(),
            credential(created, expires),
            DELEGATED_KID,
        ),
        created,
        expires,
    )
}
