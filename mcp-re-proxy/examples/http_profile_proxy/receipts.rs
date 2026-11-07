//! Responses the proof front produces other than the backend's own reply: signed rejection
//! receipts, and the translation of a profile response into a hyper one.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;

use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_proxy::http_profile_serve::continuation::ContinuationRefusal;

use crate::hpp_common;

/// A DELEGATED-signed rejection receipt (ADR-MCPRE-052): a client that requires
/// delegation must be able to READ the refusal, so a receipt is signed the same way an
/// answer is — a direct-root receipt would fail the client's own verifier and the wire
/// code would be lost.
///
/// `evidence` is `Some` once the request has verified: the receipt is then BOUND to it,
/// which is strictly stronger. Before verification there is nothing to bind to, so the
/// preflight form is used.
pub(super) fn rejection(
    request: Option<&HttpRequest>,
    evidence: Option<&RequestRoleEvidence>,
    wire_code: &'static str,
    status: u16,
) -> HttpResponse {
    let now = hpp_common::now_unix();
    let reason = RejectionReason::new(
        wire_code,
        format!("mcp-re http-profile proxy rejected: {wire_code}"),
    );
    let window = hpp_common::signing_window(now);
    match (request, evidence) {
        (Some(req), Some(_)) => build_delegated_rejection(req, &reason, status, &window),
        _ => build_delegated_rejection_preflight(request, &reason, status, &window),
    }
    .expect("rejection signs")
}

/// A request that has verified, for the refusals bound to its evidence.
pub(super) struct Verified<'a> {
    pub(super) request: &'a HttpRequest,
    pub(super) verified: &'a VerifiedMcpRequest,
}

impl Verified<'_> {
    /// A receipt bound to this request's evidence.
    pub(super) fn reject(&self, wire_code: &'static str, status: u16) -> HttpResponse {
        rejection(
            Some(self.request),
            Some(self.verified.evidence()),
            wire_code,
            status,
        )
    }

    /// The bound receipt for a continuation refusal, carrying the classification the plane
    /// stated.
    pub(super) fn reject_continuation(&self, refusal: ContinuationRefusal) -> HttpResponse {
        self.reject(refusal.error().wire_code(), refusal.status())
    }
}

/// Translate the profile `HttpResponse` (status + headers + body) into a hyper
/// response, preserving every signed header (Content-Digest, Signature-Input,
/// Signature, Content-Type).
pub(super) fn to_hyper(resp: HttpResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(Bytes::from(resp.body)))
        .expect("response builds")
}
