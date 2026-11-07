// SPDX-License-Identifier: Apache-2.0
//! The root-signed delegation credential both delegated-signing vector groups carry.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::ActorIdentity;

use super::material::CREATED;
use super::material::EXPIRES;

/// What a root key authorizes a delegated response-signing key to do.
pub(super) struct Grant<'a> {
    pub(super) issuer: &'a SigningKey,
    pub(super) issuer_kid: &'a str,
    pub(super) delegated: &'a SigningKey,
    pub(super) delegated_kid: &'a str,
    pub(super) jti: &'a str,
    pub(super) audience: &'a str,
    pub(super) audience_hash: &'a str,
    pub(super) epoch: &'a str,
}

/// The server identity a delegated key signs as; its `keyid` names the DELEGATED key,
/// the one that actually signed, while the trust seam resolves the ROOT.
pub(super) fn server_signer(delegated_kid: &str) -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: delegated_kid.into(),
    }
}

/// The compact credential the issuer signs for `grant`.
pub(super) fn issue_credential(grant: &Grant<'_>) -> String {
    let header = mcp_re_http_profile::DelegationHeader {
        typ: mcp_re_http_profile::DELEGATION_TYP.into(),
        alg: mcp_re_http_profile::DELEGATION_ALG.into(),
        kid: grant.issuer_kid.into(),
    };
    let claims = mcp_re_http_profile::DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: grant.jti.into(),
        aud: mcp_re_http_profile::Audience::One(grant.audience.into()),
        mcp_re_profile: mcp_re_http_profile::PROFILE_TAG.into(),
        mcp_re_audience_hash: grant.audience_hash.into(),
        mcp_re_server_signer: server_signer(grant.delegated_kid).actor_id(),
        mcp_re_key_use: mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: grant.delegated_kid.into(),
        issuer_kid: grant.issuer_kid.into(),
        trust_epoch: grant.epoch.into(),
        cnf: mcp_re_http_profile::Cnf {
            jwk: mcp_re_http_profile::DelegatedJwk {
                kty: mcp_re_http_profile::JWK_KTY_OKP.into(),
                crv: mcp_re_http_profile::JWK_CRV_ED25519.into(),
                kid: grant.delegated_kid.into(),
                x: grant.delegated.public_key().to_b64url(),
            },
        },
    };
    mcp_re_http_profile::issue_delegation_credential(grant.issuer, &header, &claims)
}
