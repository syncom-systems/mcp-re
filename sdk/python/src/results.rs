// SPDX-License-Identifier: Apache-2.0
//! The values the Python SDK receives back: the signed request and the two verification
//! outcomes, each a field-for-field projection of what `mcp-re-binding-core` returned.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcp_re_binding_core::Acceptance;
use mcp_re_binding_core::SignedParts;
use mcp_re_binding_core::Verdict;

/// A signed RFC 9421 request: the HTTP method + `@target-uri` + headers (carrying
/// `Signature`/`Signature-Input`/`Content-Digest`) + body, plus the request
/// evidence handle that binds a later signed response.
#[pyclass]
pub(crate) struct PySignedRequest {
    #[pyo3(get)]
    method: String,
    #[pyo3(get)]
    target_uri: String,
    #[pyo3(get)]
    headers: Vec<(String, String)>,
    body_bytes: Vec<u8>,
    #[pyo3(get)]
    evidence_digest_alg: String,
    #[pyo3(get)]
    evidence_digest_value: String,
}

#[pymethods]
impl PySignedRequest {
    /// The serialized JSON-RPC request body bytes to POST.
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body_bytes)
    }
}

impl From<SignedParts> for PySignedRequest {
    fn from(p: SignedParts) -> Self {
        PySignedRequest {
            method: p.method,
            target_uri: p.target_uri,
            headers: p.headers,
            body_bytes: p.body,
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
#[pyclass]
pub(crate) struct PyAcceptedResult {
    #[pyo3(get)]
    ok: bool,
    /// The delegated key id that signed the acknowledgement — never the root, which
    /// stays off the request path (ADR-MCPRE-052).
    #[pyo3(get)]
    server_keyid: String,
}

/// The outcome of verifying a delegated-required RFC 9421 response.
///
/// `ok` means the evidence VERIFIED (the credential chained to the trusted root and
/// the delegated signature covered the message) — it does NOT mean the request
/// succeeded. `outcome` distinguishes a verified SUCCESS (`"success"`) from a verified
/// REJECTION receipt (`"rejection"`): a delegated-signed fail-closed answer (e.g. a
/// replay or trust rejection) verifies as genuine evidence but is NOT an acceptance.
/// For a rejection, `wire_code` carries the server's frozen `mcp-re.*` reason from the
/// verified body. A caller decides acceptance on `outcome == "success"`. The remaining
/// members are [`Verdict`]'s.
#[pyclass]
pub(crate) struct PyVerifyResult {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    server_keyid: String,
    #[pyo3(get)]
    outcome: String,
    #[pyo3(get)]
    wire_code: Option<String>,
    #[pyo3(get)]
    bound: bool,
    #[pyo3(get)]
    execution_status: Option<String>,
    #[pyo3(get)]
    retry_safety: Option<String>,
    #[pyo3(get)]
    continuation_status: Option<String>,
    #[pyo3(get)]
    retention_status: Option<String>,
    #[pyo3(get)]
    resp_evidence_digest_alg: String,
    #[pyo3(get)]
    resp_evidence_digest_value: String,
    #[pyo3(get)]
    request_state: Option<String>,
}

impl From<Acceptance> for PyAcceptedResult {
    fn from(accepted: Acceptance) -> Self {
        PyAcceptedResult {
            ok: true,
            server_keyid: accepted.server_keyid,
        }
    }
}

impl From<Verdict> for PyVerifyResult {
    fn from(v: Verdict) -> Self {
        PyVerifyResult {
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
