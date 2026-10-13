// SPDX-License-Identifier: Apache-2.0
//! Emitting a delegated-key signature under a [`SigningWindow`].
//!
//! One authority: **a response is signed with the delegated key only through a window.**
//! The delegated key is crate-private to [`ActiveDelegatedKey`](super::ActiveDelegatedKey),
//! and the emitters here are the only public path to a delegated signature. Each passes the
//! window's [`DelegatedSigner`](super::DelegatedSigner) projection to a crate-private
//! emitter, so the credential, the key, the identity naming it and the validity advertised
//! are taken from ONE value and cannot be assembled from parts that disagree.

use crate::bodyless::emit_delegated_accepted_202;
use crate::error::HttpProfileError;
use crate::evidence::UnboundRequestDiagnostic;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::rejection::emit_delegated_rejection;
use crate::rejection::emit_delegated_rejection_preflight;
use crate::rejection::RejectionReason;
use crate::sign::emit_delegated_response_full;
use crate::sign::emit_delegated_response_unbound;

use super::SigningWindow;

/// Full-profile response signing for the delegated-key path (ADR-MCPRE-052 §2): the
/// response evidence block carries the inline delegation credential and the response is
/// signed by the delegated key, bound to `request`, advertising exactly `window`.
///
/// Returns the exact RFC 9421 signature base, which the delegated serving path records as
/// the input-required-response base an MRTR continuation binds to (ADR-MCPS-047).
pub fn sign_delegated_response_full(
    response: &mut HttpResponse,
    request: &HttpRequest,
    window: &SigningWindow,
) -> Result<Vec<u8>, HttpProfileError> {
    emit_delegated_response_full(response, request, &window.signer())
}

/// Response signing for the delegated-key path with NO request binding (the
/// preflight-unbound rejection case). `request_evidence_diagnostic` is recorded in the
/// block for diagnostics only and is never a trusted request binding.
pub fn sign_delegated_response_unbound(
    response: &mut HttpResponse,
    request_evidence_diagnostic: &UnboundRequestDiagnostic,
    window: &SigningWindow,
) -> Result<(), HttpProfileError> {
    emit_delegated_response_unbound(response, request_evidence_diagnostic, &window.signer())
}

/// A delegated bodyless `202 Accepted` for a notification, signed under `window` and
/// carrying the compact-JWS delegation credential in the `mcp-re-delegation` header.
pub fn sign_delegated_accepted_202(
    request: &HttpRequest,
    window: &SigningWindow,
) -> Result<HttpResponse, HttpProfileError> {
    emit_delegated_accepted_202(request, &window.signer())
}

/// A request-bound delegated rejection signed under `window`: the request verified far
/// enough to trust its hash but failed a later gate.
pub fn build_delegated_rejection(
    request: &HttpRequest,
    reason: &RejectionReason,
    status: u16,
    window: &SigningWindow,
) -> Result<HttpResponse, HttpProfileError> {
    emit_delegated_rejection(request, reason, status, &window.signer())
}

/// A preflight (unbound) delegated rejection signed under `window`: no trustworthy request
/// hash exists, so the response is signed over its own components only.
pub fn build_delegated_rejection_preflight(
    received: Option<&HttpRequest>,
    reason: &RejectionReason,
    status: u16,
    window: &SigningWindow,
) -> Result<HttpResponse, HttpProfileError> {
    emit_delegated_rejection_preflight(received, reason, status, &window.signer())
}

#[cfg(test)]
mod tests {
    // The emitters are exercised end to end by `delegation_e2e_test` and the proxy serving
    // batteries; what is pinned here is that a window's validity is what a signature carries.
    use super::super::signing_window::tests::key;
    use super::*;

    /// A response signed under a window advertises that window's `created` and `expires`,
    /// not any other pair.
    #[test]
    fn a_signature_advertises_exactly_the_windows_validity() {
        let window = SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential");
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec(),
        };
        let diagnostic = UnboundRequestDiagnostic::absent();
        sign_delegated_response_unbound(&mut response, &diagnostic, &window)
            .expect("signs under the window");
        let input = response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("signature-input"))
            .map(|(_, v)| v.clone())
            .expect("signature-input");
        assert!(input.contains("created=1000"), "{input}");
        assert!(input.contains("expires=1030"), "{input}");
    }
}
