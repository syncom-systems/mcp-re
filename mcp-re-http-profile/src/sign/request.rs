// SPDX-License-Identifier: Apache-2.0
//! Request-side signing: the covered-component selection, the routing-header derivation and
//! the RFC 9421 signature emission for a request, for a local key and for an external signer.

use mcp_re_core::SigningKey;

use crate::block::HttpRequestEvidenceBlock;
use crate::body::insert_meta_block;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestRoleEvidence;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
use crate::message::reject_content_encoding;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;

use super::emit_signature;
use super::local_sig;
use super::profile_params;
use super::set_header;

fn request_components(request: &HttpRequest) -> Result<Vec<CoveredComponent>, HttpProfileError> {
    let mut components: Vec<CoveredComponent> = REQUIRED_REQUEST_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    components.extend(conditional_request_components(&request.headers)?);
    Ok(components)
}

/// The conditionally-covered components for `headers`: one per mandatory-if-present
/// request header actually on the wire (v0.11 grill B.1 for the credential surface,
/// #415 rev 2 §4.1 for the MCP transport headers).
///
/// Reads the SAME set the verifier requires
/// (`verify::conditionally_covered_request_headers`), so the signer covers exactly what
/// the verifier will insist on, and only what is present. Exactly-once is enforced by
/// `single_header`'s duplicate rejection. Shared with the BODYLESS signer.
pub(crate) fn conditional_request_components(
    headers: &[(String, String)],
) -> Result<Vec<CoveredComponent>, HttpProfileError> {
    let mut components = Vec::new();
    for header in crate::verify::floor::components::conditionally_covered_request_headers() {
        if single_header(headers, header)?.is_some() {
            components.push(CoveredComponent::new(header));
        }
    }
    Ok(components)
}

/// The RFC 9421 signature parameters one request signature states: who signs, when the
/// signature was created and stops being valid, and the nonce that makes it single-use.
#[derive(Debug, Clone, Copy)]
pub struct RequestSignature<'a> {
    pub key_id: &'a str,
    pub created: i64,
    pub expires: i64,
    pub nonce: &'a str,
}

impl RequestSignature<'_> {
    fn params(&self) -> SignatureParams {
        profile_params(self.key_id, self.created, self.expires, Some(self.nonce))
    }
}

/// Sign `request` in place with a local in-process [`SigningKey`]: emit
/// `Content-Digest`, `Signature-Input`, and `Signature` (label `mcp-re`, tag
/// `mcp-re-http-v1`). Returns the [`RequestRoleEvidence`] handle derived from the
/// exact signature base. A thin local-key wrapper over
/// [`sign_request_with_signer`].
pub fn sign_request(
    request: &mut HttpRequest,
    key: &SigningKey,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    sign_request_with_signer(request, |base| local_sig(key, base), signature)
}

/// Sign `request` in place with an EXTERNAL signer (Cloud KMS / HSM custody).
///
/// Wire-identical to [`sign_request`]: the profile owns `Content-Digest`, covered-component
/// selection, the signature base and header assembly — only the private-key operation is
/// delegated. `sign_base` receives the EXACT signature-base bytes and MUST return exactly
/// the 64 raw Ed25519 signature bytes (enforced). This is the seam a production deployment
/// uses to keep the signing key in a KMS/HSM.
pub fn sign_request_with_signer(
    request: &mut HttpRequest,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    // The routing headers the contract requires, derived from the body this signature
    // protects, so the signer cannot be the source of a header/body disagreement.
    crate::mcp_transport::add_contract_headers(request)?;
    sign_headers_as_given(request, sign_base, signature)
}

/// Sign `request` with a local key over exactly the headers it already carries: no routing
/// header is derived. For a caller that states its own transport headers on purpose,
/// including one building a request the verifier is meant to refuse.
pub fn sign_request_as_given(
    request: &mut HttpRequest,
    key: &SigningKey,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    sign_headers_as_given(request, |base| local_sig(key, base), signature)
}

fn sign_headers_as_given(
    request: &mut HttpRequest,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    // Every request signer ends here, so this is the one place a carried block is checked.
    super::request_block::validate_carried(&request.body)?;
    set_header(
        &mut request.headers,
        "Content-Digest",
        content_digest_sha256(&request.body),
    );

    let components = request_components(request)?;
    let params = signature.params();
    let base = signature_base(&components, &params, &SourceMessage::Request(request))?;
    emit_signature(
        &mut request.headers,
        REQUEST_LABEL,
        &components,
        &params,
        &base,
        sign_base,
    )?;
    Ok(RequestRoleEvidence::from_signature_base(&base))
}

/// Compose the request evidence block (`se.syncom/mcp-re.http.request`) into the JSON-RPC
/// body `_meta` FIRST, so `content-digest` (a covered component) protects the block.
fn compose_evidence_block(
    request: &mut HttpRequest,
    block: &HttpRequestEvidenceBlock,
) -> Result<(), HttpProfileError> {
    request.body = insert_meta_block(&request.body, REQUEST_EVIDENCE_BLOCK_KEY, block)?;
    Ok(())
}

/// Full-profile request signing (MCPRE-101): compose the request evidence block
/// (`se.syncom/mcp-re.http.request`) into the JSON-RPC body `_meta` FIRST, then
/// sign — so `content-digest` (a covered component) protects the block. Returns
/// the [`RequestRoleEvidence`] handle over the resulting signature base; pass it to
/// [`crate::custody::sign_delegated_response_full`] so the response can carry `request_evidence`.
pub fn sign_request_full(
    request: &mut HttpRequest,
    block: &HttpRequestEvidenceBlock,
    key: &SigningKey,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    compose_evidence_block(request, block)?;
    sign_request(request, key, signature)
}

/// Full-profile request signing through an EXTERNAL signer (Cloud KMS / HSM
/// custody). Like [`sign_request_full`] except the private-key operation is
/// delegated to `sign_base` (which receives the exact RFC 9421 signature base and
/// MUST return the 64 raw Ed25519 signature bytes). The evidence block is composed
/// FIRST so `content-digest` (a covered component) protects it, exactly as the
/// local-key path does.
pub fn sign_request_full_with_signer(
    request: &mut HttpRequest,
    block: &HttpRequestEvidenceBlock,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    signature: &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError> {
    compose_evidence_block(request, block)?;
    sign_request_with_signer(request, sign_base, signature)
}
