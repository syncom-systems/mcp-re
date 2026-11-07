// SPDX-License-Identifier: Apache-2.0
//! Shared harness for the ROOT-AUTHORITY lifecycle lanes (ADR-MCPRE-052): a
//! `TestRootAuthorityProvider` that mints disposable roots, and a single
//! `run_rotation_scenario` the hermetic (in-memory) and live (Cloud KMS) lanes both
//! drive — so the two prove the SAME trust-anchor rotation/overlap/revocation, only
//! the root SOURCE differs (in-memory keys vs KMS-held keys).
//!
//! This is test-support, never shipped. The production root-rotation controller is a
//! separate, governed mechanism (see docs/spec/root-authority-rotation.md); this
//! provisions throwaway roots so the lifecycle can be tested WITHOUT a human creating
//! a KMS key for every run.

#![allow(dead_code)] // each test binary uses a subset

mod rotation;

pub use rotation::run_rotation_scenario;

use mcp_re_client_core::ManifestIssuer;
use mcp_re_client_core::RetiringIssuer;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;

use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;

pub const AUD: &str = "verifier-1";
pub const AUD_SCOPE: &str = "aud-scope-1";
pub const EPOCH: &str = "epoch-1";
pub const SERVER_SIGNER: &str = "server:example.com:did:example:server:server-key";
pub const ORG_KID: &str = "org-admin-manifest-key";

/// A minted trust anchor: its id, its public key, and a signer over the JWS signing
/// input (raw 64-byte Ed25519). In-memory roots wrap a local key; KMS roots wrap a
/// Cloud KMS `asymmetricSign` call — both feed the SAME issuance seam.
/// A signer over the JWS signing input, returning a raw 64-byte Ed25519 signature.
pub type RootSignFn = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

pub struct RootAuthority {
    pub issuer_kid: String,
    pub public_key: VerificationKey,
    sign: RootSignFn,
}

impl RootAuthority {
    /// Wrap an explicit signer (used by the live KMS lane).
    pub fn new(
        issuer_kid: impl Into<String>,
        public_key: VerificationKey,
        sign: RootSignFn,
    ) -> Self {
        RootAuthority {
            issuer_kid: issuer_kid.into(),
            public_key,
            sign,
        }
    }

    fn sign_raw(&self, input: &[u8]) -> Vec<u8> {
        (self.sign)(input)
    }

    /// Mint a delegation credential (compact JWS) under this root for a fresh
    /// delegated key, returning `(compact_jws, delegated_kid)`.
    pub fn issue_credential(&self, delegated: &SigningKey, seq: u32, now: i64) -> String {
        let delegated_kid = format!("{}/delegated/{seq}", self.issuer_kid);
        let header = DelegationHeader {
            typ: DELEGATION_TYP.into(),
            alg: DELEGATION_ALG.into(),
            kid: self.issuer_kid.clone(),
        };
        let claims = DelegationClaims {
            iss: "did:example:issuer".into(),
            iat: now,
            nbf: now,
            exp: now + 300,
            jti: format!("evt-{}-{seq}", self.issuer_kid),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_audience_hash: AUD_SCOPE.into(),
            mcp_re_server_signer: SERVER_SIGNER.into(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            delegated_kid: delegated_kid.clone(),
            issuer_kid: self.issuer_kid.clone(),
            trust_epoch: EPOCH.into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: delegated_kid.clone(),
                    x: delegated.public_key().to_b64url(),
                },
            },
        };
        issue_delegation_credential_with_signer(&header, &claims, |input| Ok(self.sign_raw(input)))
            .expect("root signs a 64-byte credential")
    }

    fn as_manifest_issuer(&self) -> ManifestIssuer {
        ManifestIssuer {
            issuer_kid: self.issuer_kid.clone(),
            public_key: self.public_key.to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
        }
    }

    fn as_retiring_issuer(&self, valid_until: i64) -> RetiringIssuer {
        let issuer = self.as_manifest_issuer();
        RetiringIssuer {
            issuer_kid: issuer.issuer_kid,
            public_key: issuer.public_key,
            role: issuer.role,
            trust_domain: issuer.trust_domain,
            subject: issuer.subject,
            valid_until,
        }
    }
}

/// A provider that mints disposable roots on demand — the "no human creates a key"
/// mechanism. Hermetic tests use [`InMemoryTestRootAuthorityProvider`]; the live lane
/// constructs KMS-backed [`RootAuthority`]s directly from provisioned key versions.
pub trait TestRootAuthorityProvider {
    fn create_root(&mut self, label: &str) -> RootAuthority;
}

/// Mints in-memory Ed25519 roots — the hermetic analogue of the KMS provisioner.
pub struct InMemoryTestRootAuthorityProvider {
    seed: u8,
}

impl InMemoryTestRootAuthorityProvider {
    pub fn new() -> Self {
        InMemoryTestRootAuthorityProvider { seed: 40 }
    }
}

impl TestRootAuthorityProvider for InMemoryTestRootAuthorityProvider {
    fn create_root(&mut self, label: &str) -> RootAuthority {
        self.seed = self.seed.wrapping_add(1);
        let key = SigningKey::from_seed_bytes(&[self.seed; 32]);
        let public_key = key.public_key();
        RootAuthority::new(
            format!("inmem-root-{label}"),
            public_key,
            Box::new(move |input: &[u8]| {
                b64url_decode(&key.sign(input)).expect("own signature is valid base64url")
            }),
        )
    }
}
