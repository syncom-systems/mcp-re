// SPDX-License-Identifier: Apache-2.0
//! Minting a delegation credential — the ROOT custody seam (ADR-MCPS-028).
//!
//! A different authority from [`super::verify`], and deliberately so. Verification decides
//! whether a credential may be believed and runs on every request; issuance holds the §2
//! root, runs at rotation, and in the deployment that matters does not hold the root key at
//! all — a Cloud KMS or HSM signs the credential and the private key never exists in this
//! process.
//!
//! The seam is where the two meet, and it is checked here rather than trusted: an external
//! signer that hands back a DER-wrapped or truncated signature is a contract violation, and
//! catching it at issuance is what stops it being emitted as a malformed credential that
//! every verifier then refuses.

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;

use super::jose::CompactJws;
use super::jose::IssueDefect;
use crate::error::HttpProfileError;

use super::DelegationClaims;
use super::DelegationHeader;

/// Issue (mint) a compact JWS delegation credential using an EXTERNAL root signer
/// — the Cloud KMS / HSM custody seam (ADR-MCPS-028), where the ADR-MCPRE-052 §2
/// root is held OFF the hot path and signs ONLY the credential at issuance /
/// rotation. The root private key never has to exist in this process.
///
/// `sign_root` receives the exact JWS signing input
/// (`base64url(header) "." base64url(claims)`, ASCII) and MUST return exactly the
/// 64 raw Ed25519 signature bytes (RFC 8037); any other length is rejected
/// `DelegationCredentialInvalid` rather than emitted. This is the KMS-capable
/// sibling of [`issue_delegation_credential`] (which requires an in-process
/// [`SigningKey`]); both route through the same builder, so the compact-JWS wire
/// bytes are identical for the same key and claims.
///
/// The caller builds a consistent pair: `typ`/`alg` pinned, header `kid` ==
/// claims `issuer_kid`, and `cnf.jwk` == the delegated key.
pub fn issue_delegation_credential_with_signer(
    header: &DelegationHeader,
    claims: &DelegationClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    // A credential this function cannot form gets the verdict a verifier would give it; a
    // signer's own refusal is propagated as it stands.
    CompactJws::issue(header, claims, sign_root).map_err(|defect| match defect {
        IssueDefect::Unformable | IssueDefect::SignatureLength => {
            HttpProfileError::DelegationCredentialInvalid
        }
        IssueDefect::Signer(e) => e,
    })
}

/// Issue (mint) a compact JWS delegation credential with an IN-PROCESS root key
/// (ADR-MCPRE-052 §1) — the software-key path. Routes through
/// [`issue_delegation_credential_with_signer`], so it is wire-identical to the
/// KMS/HSM seam for the same key and claims. Production with the root in KMS/HSM
/// uses the signer seam instead, keeping the root off the hot path.
// The one assertion on this path is about THIS crate's own primitives, never about an
// input — see the note at the `expect` below.
#[allow(clippy::expect_used)]
pub fn issue_delegation_credential(
    root_key: &SigningKey,
    header: &DelegationHeader,
    claims: &DelegationClaims,
) -> String {
    issue_delegation_credential_with_signer(header, claims, |input| {
        // `SigningKey::sign` returns Base64URL; decode to the raw 64 bytes the
        // seam contract speaks. An in-process Ed25519 signer is always 64 bytes.
        b64url_decode(&root_key.sign(input))
            .map_err(|_| HttpProfileError::DelegationCredentialInvalid)
    })
    // Class A, about THIS crate rather than any input: `header`/`claims` are plain
    // `Serialize` structs, `b64url_decode` inverts the `b64url_encode` `SigningKey::sign`
    // just applied, and an in-process Ed25519 signature is 64 bytes by construction. No
    // configuration, peer, clock or provider participates.
    .expect("the in-process signer's own serialization, encoding and signature length")
}
