// SPDX-License-Identifier: Apache-2.0
//! The issuer/custody side (root-signed credentials) and the delegated responses the
//! vectors freeze, including the deliberately wrong ones.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::ActiveDelegatedKey;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::rejection::pre_052_direct_root::sign_pre_052_direct_root_response_for_negative_test;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;

use super::material::delegated_key;
use super::material::response_body;
use super::material::root_key;
use super::material::server_signer_for;
use super::material::AUD_SCOPE;
use super::material::CREATED;
use super::material::DELEGATED_KID;
use super::material::EPOCH;
use super::material::EXPIRES;
use super::material::ROOT_KID;
use super::material::VERIFIER_AUD;

pub(super) fn good_header() -> DelegationHeader {
    DelegationHeader {
        typ: DELEGATION_TYP.into(),
        alg: DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    }
}

/// A nominal, in-every-way-valid claim set binding `delegated` under
/// `delegated_kid`, scoped to this verifier / profile / audience / epoch.
pub(super) fn good_claims(delegated: &SigningKey, delegated_kid: &str) -> DelegationClaims {
    DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: "evt-1".into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: server_signer_for(delegated_kid).actor_id(),
        mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: delegated_kid.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: JWK_KTY_OKP.into(),
                crv: JWK_CRV_ED25519.into(),
                kid: delegated_kid.into(),
                x: delegated.public_key().to_b64url(),
            },
        },
    }
}

pub(super) fn mint(
    root: &SigningKey,
    header: &DelegationHeader,
    claims: &DelegationClaims,
) -> String {
    issue_delegation_credential(root, header, claims)
}

/// The single canonical valid credential for the primary delegated key.
pub(super) fn valid_credential() -> String {
    mint(
        &root_key(),
        &good_header(),
        &good_claims(&delegated_key(), DELEGATED_KID),
    )
}

/// What signs a delegated response and what it claims to be signed by.
///
/// A vector where `keyid` and `block_signer_kid` differ is a response no product
/// window signs: the window's key is stated here, so the block can name one kid
/// and the signature another.
pub(super) struct ResponseSigning<'a> {
    /// The compact-JWS credential the response embeds.
    pub(super) credential: &'a str,
    /// The key that makes the RFC 9421 signature.
    pub(super) signing_key: fn() -> SigningKey,
    /// The RFC 9421 `keyid`.
    pub(super) keyid: &'a str,
    /// The `server_signer.keyid` the evidence block names.
    pub(super) block_signer_kid: &'a str,
}

impl<'a> ResponseSigning<'a> {
    /// The primary delegated key signing under its own kid with `credential`.
    pub(super) fn primary(credential: &'a str) -> Self {
        ResponseSigning {
            credential,
            signing_key: delegated_key,
            keyid: DELEGATED_KID,
            block_signer_kid: DELEGATED_KID,
        }
    }
}

fn json_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    }
}

/// Sign a fresh delegated response for `req` as described by `signing`.
pub(super) fn delegated_response(req: &HttpRequest, signing: &ResponseSigning) -> HttpResponse {
    let mut rsp = json_response();
    sign_delegated_response_full(
        &mut rsp,
        req,
        &SigningWindow::stated(
            ActiveDelegatedKey::stated(
                (signing.signing_key)(),
                server_signer_for(signing.block_signer_kid),
                signing.credential,
                signing.keyid,
            ),
            CREATED,
            EXPIRES,
        ),
    )
    .expect("sign delegated response");
    rsp
}

/// The valid delegated response (its own signed bytes), freshly signed so a
/// post-signing tamper does not disturb a shared copy.
pub(super) fn valid_response(req: &HttpRequest) -> HttpResponse {
    delegated_response(req, &ResponseSigning::primary(&valid_credential()))
}

/// A response signed directly by `key` under `kid` with NO delegation credential.
pub(super) fn credentialless_response(
    req: &HttpRequest,
    ev: &RequestRoleEvidence,
    key: &SigningKey,
    kid: &str,
) -> HttpResponse {
    let mut rsp = json_response();
    sign_pre_052_direct_root_response_for_negative_test(
        &mut rsp,
        req,
        ev,
        &server_signer_for(kid),
        key,
        kid,
        CREATED,
        EXPIRES,
    )
    .expect("sign credential-less response");
    rsp
}

/// Flip one base64url character inside the `mcp-re-response` Signature value,
/// keeping it a well-formed header but a wrong signature.
pub(super) fn tamper_response_signature(rsp: &mut HttpResponse) {
    for (_, value) in rsp
        .headers
        .iter_mut()
        .filter(|(name, _)| name.eq_ignore_ascii_case("signature"))
    {
        flip_signature_byte(value);
    }
}

/// Value form `mcp-re-response=:<b64>:` — flip a character inside the base64, a
/// few places after the `:` that opens the byte sequence.
fn flip_signature_byte(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    let target = bytes
        .iter()
        .position(|&b| b == b':')
        .map(|colon| colon + 3)
        .filter(|&idx| idx < bytes.len());
    if let Some(idx) = target {
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
    }
    *value = String::from_utf8(bytes).expect("a signature header is ASCII");
}
