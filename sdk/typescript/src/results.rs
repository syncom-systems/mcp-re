// SPDX-License-Identifier: Apache-2.0
//! The values the TypeScript SDK receives back: the signed request and the two verification
//! outcomes, each a field-for-field projection of what `mcp-re-binding-core` returned.

use mcp_re_binding_core::Acceptance;
use mcp_re_binding_core::SignedParts;
use mcp_re_binding_core::Verdict;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use super::HttpHeader;

/// A signed RFC 9421 request.
#[napi(object)]
pub struct SignedRequestJs {
    pub method: String,
    pub target_uri: String,
    pub headers: Vec<HttpHeader>,
    pub body: Buffer,
    pub evidence_digest_alg: String,
    pub evidence_digest_value: String,
}

impl From<SignedParts> for SignedRequestJs {
    fn from(p: SignedParts) -> Self {
        SignedRequestJs {
            method: p.method,
            target_uri: p.target_uri,
            headers: p
                .headers
                .into_iter()
                .map(|(key, value)| HttpHeader { key, value })
                .collect(),
            body: Buffer::from(p.body),
            evidence_digest_alg: p.evidence_digest_alg,
            evidence_digest_value: p.evidence_digest_value,
        }
    }
}

/// The outcome of verifying a delegated-signed bodyless `202 Accepted`.
///
/// `ok` means the acknowledgement VERIFIED: the credential chained to the trusted root
/// and the delegated signature covered the acknowledgement AND bound it to the exact
/// notification transmission this client sent.
///
/// **What that claims, exactly: the enforcement boundary authenticated and accepted the
/// message.** NOT that the action completed, that the inner application observed it, or
/// that anything was done about it — a verified acknowledgement of
/// `notifications/cancelled` does not mean anything was cancelled.
#[napi(object)]
pub struct AcceptedResultJs {
    pub ok: bool,
    /// The delegated key id that signed the acknowledgement — never the root, which
    /// stays off the request path (ADR-MCPRE-052).
    pub server_keyid: String,
}

impl From<Acceptance> for AcceptedResultJs {
    fn from(accepted: Acceptance) -> Self {
        AcceptedResultJs {
            ok: true,
            server_keyid: accepted.server_keyid,
        }
    }
}

/// The outcome of verifying a delegated-required RFC 9421 response; the members are
/// `mcp-re-binding-core`'s `Verdict`.
#[napi(object)]
pub struct VerifyResultJs {
    /// The evidence VERIFIED; this does NOT mean the request succeeded. A caller
    /// decides acceptance on `outcome === "success"`.
    pub ok: bool,
    pub server_keyid: String,
    /// `"success"` for an accepted answer; `"rejection"` for a verified rejection
    /// receipt — genuine evidence, but NOT an acceptance.
    pub outcome: String,
    /// The wire code carried by a verified rejection receipt; absent on success.
    pub wire_code: Option<String>,
    /// Whether a rejection receipt is bound to this client's request.
    pub bound: bool,
    /// The ADR-MCPRE-058 §10 execution/retry contract the server derived from its
    /// exchange machine and signed into the rejection body. Absent on success and on a
    /// receipt that stated nothing.
    ///
    /// An ABSENT `execution_status` is not `"not_executed"`. The server states a
    /// disposition when it has one, and collapsing silence into "nothing ran" is
    /// exactly the read that makes a post-dispatch refusal look retry-safe.
    pub execution_status: Option<String>,
    /// `retry_safety`: what a retry of this refused request would cost.
    pub retry_safety: Option<String>,
    /// `continuation_status`: whether the exchange consumed a human approval.
    pub continuation_status: Option<String>,
    /// `retention_status`: whether the server's evidence-retention obligation failed.
    pub retention_status: Option<String>,
    /// The verified response's evidence-handle digest algorithm — the
    /// `input_required_response_evidence` handle an MRTR answer leg binds to
    /// (ADR-MCPS-047). Read from the VERIFIED response only.
    pub resp_evidence_digest_alg: String,
    /// The verified response's evidence-handle digest value (base64url, no pad).
    pub resp_evidence_digest_value: String,
    /// `result.requestState` (a string) from the verified response body IFF the
    /// audited classifier reads it as an `InputRequiredResult`; else absent. The
    /// opaque MRTR state the answer leg re-presents. Read only after the response
    /// verified as genuine evidence.
    ///
    /// The discriminator itself is deliberately not restated here — it lives in
    /// `mcp_re_http_profile::result_class`, and a doc comment repeating it is one
    /// more copy to drift. A verified reply that declares itself non-terminal
    /// without a usable state is an ERROR, never an absent state.
    pub request_state: Option<String>,
}

impl From<Verdict> for VerifyResultJs {
    fn from(v: Verdict) -> Self {
        VerifyResultJs {
            ok: true,
            server_keyid: v.server_keyid,
            outcome: v.outcome.to_owned(),
            wire_code: v.wire_code,
            bound: v.bound,
            execution_status: v.execution_status,
            retry_safety: v.retry_safety,
            continuation_status: v.continuation_status,
            retention_status: v.retention_status,
            resp_evidence_digest_alg: v.resp_evidence_digest_alg,
            resp_evidence_digest_value: v.resp_evidence_digest_value,
            request_state: v.request_state,
        }
    }
}
