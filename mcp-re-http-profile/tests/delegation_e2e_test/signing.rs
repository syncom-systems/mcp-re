// SPDX-License-Identifier: Apache-2.0
//! Response emitters for the delegated-signing battery: the library's honest signers, and the
//! forged messages only a hand-built emitter can produce.

use super::fixtures::{
    delegated_key, json_response, root_key, server_signer, signed_request, valid_credential,
    CREATED, DELEGATED_KID, EXPIRES,
};
use mcp_re_core::SigningKey;
use mcp_re_http_profile::body::insert_meta_block;
use mcp_re_http_profile::custody::ActiveDelegatedKey;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::evidence::UnboundRequestDiagnostic;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_delegated_response_unbound;
use mcp_re_http_profile::sign_response_with_signer;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::HttpResponseEvidenceBlock;
use mcp_re_http_profile::RequestEvidenceDigest;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_http_profile::RESPONSE_EVIDENCE_BLOCK_KEY;

/// The window a delegated response is signed under: `key` signing as the delegated signer
/// with the valid credential. Pass a key other than the delegated one for the keyid-matches-
/// key-does-not case.
pub fn delegated_window(key: SigningKey) -> SigningWindow {
    SigningWindow::stated(
        ActiveDelegatedKey::stated(key, server_signer(), valid_credential(), DELEGATED_KID),
        CREATED,
        EXPIRES,
    )
}

/// A request-bound delegated response to `request`, signed by `key`.
pub fn bound_response_signed_by(request: &HttpRequest, key: SigningKey) -> HttpResponse {
    let mut rsp = json_response(200);
    sign_delegated_response_full(&mut rsp, request, &delegated_window(key))
        .expect("sign delegated response");
    rsp
}

/// A delegated PREFLIGHT receipt (no request binding) for `request`, signed by `key`.
pub fn unbound_receipt_signed_by(request: &HttpRequest, key: SigningKey) -> HttpResponse {
    let mut rsp = json_response(400);
    sign_delegated_response_unbound(
        &mut rsp,
        &UnboundRequestDiagnostic::received(&request.body),
        &delegated_window(key),
    )
    .expect("sign unbound delegated receipt");
    rsp
}

/// A fresh request and the bound delegated response signed over it by the delegated key.
pub fn signed_delegated_bound() -> (HttpRequest, HttpResponse) {
    let (req, _, _) = signed_request();
    let rsp = bound_response_signed_by(&req, delegated_key());
    (req, rsp)
}

/// A fresh delegated preflight receipt signed by the delegated key.
pub fn signed_delegated_unbound() -> HttpResponse {
    let (req, _, _) = signed_request();
    unbound_receipt_signed_by(&req, delegated_key())
}

/// The block a forged delegated response advertises, and the wire keyid it is signed under.
pub struct Forgery<'a> {
    /// The identity the evidence block names as the server signer.
    pub signer: &'a ActorIdentity,
    /// The inline delegation credential.
    pub credential: &'a str,
    /// The RFC 9421 keyid the signature is made under.
    pub wire_kid: &'a str,
}

impl<'a> Forgery<'a> {
    /// The honest block and wire keyid, for the caller to override one field of.
    pub fn honest(signer: &'a ActorIdentity, credential: &'a str) -> Self {
        Self {
            signer,
            credential,
            wire_kid: DELEGATED_KID,
        }
    }

    fn block(&self, request_evidence: RequestEvidenceDigest) -> HttpResponseEvidenceBlock {
        HttpResponseEvidenceBlock {
            profile: PROFILE_TAG.to_owned(),
            server_signer: self.signer.clone(),
            server_delegation: Some(self.credential.to_owned()),
            request_evidence,
        }
    }
}

/// What only a hand-built emitter can produce: a bound delegated response whose block names
/// `forgery.signer` while the signature is made under `forgery.wire_kid`, and whose block
/// advertises `advertised`'s handle while `;req` resolves over `request`. The library's
/// delegated signers refuse such pairs, so the verifier's refusal is exercised over a forged
/// message.
pub fn forge_bound(
    request: &HttpRequest,
    advertised: &RequestRoleEvidence,
    forgery: &Forgery<'_>,
) -> HttpResponse {
    let mut rsp = json_response(200);
    let block = forgery.block(advertised.to_digest());
    rsp.body = insert_meta_block(&rsp.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block).expect("insert");
    sign_response_with_signer(
        &mut rsp,
        request,
        |b| {
            mcp_re_core::b64url_decode(&delegated_key().sign(b))
                .map_err(|_| HttpProfileError::InvalidSignature)
        },
        forgery.wire_kid,
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    rsp
}

/// [`forge_bound`] with the honest signer, credential and wire keyid: only the advertised
/// request-evidence handle is forged.
pub fn forge_bound_over_valid_credential(
    request: &HttpRequest,
    advertised: &RequestRoleEvidence,
) -> HttpResponse {
    forge_bound(
        request,
        advertised,
        &Forgery::honest(&server_signer(), &valid_credential()),
    )
}

/// The unbound analogue of [`forge_bound`].
pub fn forge_unbound(request: &HttpRequest, forgery: &Forgery<'_>) -> HttpResponse {
    let mut rsp = json_response(400);
    let block = forgery.block(UnboundRequestDiagnostic::received(&request.body).to_digest());
    rsp.body = insert_meta_block(&rsp.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block).expect("insert");
    mcp_re_http_profile::sign::sign_response_unbound(
        &mut rsp,
        &delegated_key(),
        forgery.wire_kid,
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    rsp
}

/// A root-signed unbound response with no delegation credential: the credential is stripped
/// from the covered block of `receipt` before the root signs it, so the digest changes with
/// it and this is the "no credential presented" case rather than a tamper.
pub fn root_signed_without_a_credential(receipt: &HttpResponse) -> HttpResponse {
    let mut stripped: serde_json::Value = serde_json::from_slice(&receipt.body).expect("body");
    stripped["_meta"]["se.syncom/mcp-re.http.response"]
        .as_object_mut()
        .expect("response block")
        .remove("server_delegation");
    let mut plain = json_response(400);
    plain.body = serde_json::to_vec(&stripped).expect("re-encode");
    mcp_re_http_profile::sign::sign_response_unbound(
        &mut plain,
        &root_key(),
        super::fixtures::ROOT_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign root-signed unbound response");
    plain
}

/// Flip a byte inside the covered body, so the content digest no longer matches.
pub fn flip_a_body_byte(rsp: &mut HttpResponse) {
    let last = rsp.body.len() - 2;
    rsp.body[last] ^= 0x01;
}

/// Declare a content coding the profile forbids.
pub fn add_content_encoding(rsp: &mut HttpResponse) {
    rsp.headers.push(("Content-Encoding".into(), "gzip".into()));
}

fn set_header(rsp: &mut HttpResponse, name: &str, value: &str) {
    let slot = rsp
        .headers
        .iter_mut()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .expect("header present");
    slot.1 = value.into();
}

/// Re-declare the response as an event stream rather than JSON.
pub fn make_event_stream(rsp: &mut HttpResponse) {
    set_header(rsp, "Content-Type", "text/event-stream");
}

/// Remove the covered `@method;req` item from the signature input.
pub fn uncover_the_req_method(rsp: &mut HttpResponse) {
    let (_, input) = rsp
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("signature-input"))
        .expect("signature-input present")
        .clone();
    let stripped = input.replacen(" \"@method\";req", "", 1);
    assert_ne!(
        stripped, input,
        "the covered `@method;req` item was removed"
    );
    set_header(rsp, "Signature-Input", &stripped);
}
