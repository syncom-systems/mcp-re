// SPDX-License-Identifier: Apache-2.0
//! PyO3 binding exposing the audited `mcp-re-client-core` RFC 9421 signing /
//! verification seam to the MCP-RE Python SDK (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest — the SDK
//! signs and verifies the HTTP evidence carrier only; the signature rides in the HTTP
//! headers, not a JSON-RPC `_meta` block.
//!
//! Two custody classes are exposed (ADR-MCPS-044 §Compliance): `sign_request` takes a
//! raw seed (software custody), and `sign_request_with_signer` takes only a sign
//! callback, so the private key never enters the SDK (non-exporting custody).
//!
//! This file marshals Python values into `mcp-re-binding-core` and its results back; the
//! signing inputs, the device check, the root anchor, the verify preamble and the verdict
//! are that crate's, shared with the N-API binding.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcp_re_binding_core::BindingError;
use mcp_re_binding_core::Call;
use mcp_re_binding_core::ContinuationArgs;
use mcp_re_binding_core::IssuerField;
use mcp_re_binding_core::PinnedIssuer;
use mcp_re_binding_core::SignArgs;
use mcp_re_binding_core::SignedParts;
use mcp_re_binding_core::Verdict;
use mcp_re_binding_core::VerifyArgs;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;

/// An issuer field by the keyword the Python API takes it as.
fn field_name(field: IssuerField) -> &'static str {
    match field {
        IssuerField::KeyId => "issuer_key_id",
        IssuerField::Role => "issuer_role",
        IssuerField::TrustDomain => "issuer_trust_domain",
        IssuerField::Subject => "issuer_subject",
    }
}

/// A binding refusal as the `ValueError` the Python SDK raises.
fn raise(e: BindingError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.message(field_name))
}

/// A device callback as the core's device seam: the signature bytes, or `None` when the
/// callback raised or returned something that is not bytes.
fn device<'a>(
    py: Python<'a>,
    sign_callback: &'a Py<PyAny>,
) -> impl FnOnce(&[u8]) -> Option<Vec<u8>> + 'a {
    move |preimage: &[u8]| {
        let out = sign_callback
            .call1(py, (PyBytes::new(py, preimage),))
            .ok()?;
        out.extract(py).ok()
    }
}

/// The audited core's version — `mcp-re-client-core`'s, not this binding crate's.
#[pyfunction]
fn core_version() -> &'static str {
    mcp_re_binding_core::CORE_VERSION
}

/// The RFC 9421 profile tag the signature is emitted/verified under.
#[pyfunction]
fn profile_tag() -> &'static str {
    mcp_re_binding_core::PROFILE_TAG
}

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature — the primitive a `SigningDevice` (the HSM/KMS stand-in) is built on.
///
/// This is the same operation the software signing path performs internally, so a
/// device-delegated signature is byte-identical to the in-process one.
#[pyfunction]
fn sign_preimage<'py>(
    py: Python<'py>,
    seed: &[u8],
    preimage: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sig = mcp_re_binding_core::sign_preimage(seed, preimage).map_err(raise)?;
    Ok(PyBytes::new(py, &sig))
}

/// A signed RFC 9421 request: the HTTP method + `@target-uri` + headers (carrying
/// `Signature`/`Signature-Input`/`Content-Digest`) + body, plus the request
/// evidence handle that binds a later signed response.
#[pyclass]
struct PySignedRequest {
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

/// The arguments every signing entry point shares, in the order the Python API takes them.
#[allow(clippy::too_many_arguments)]
fn sign_args(
    call: Call,
    key_id: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> SignArgs {
    SignArgs {
        call,
        key_id: key_id.to_owned(),
        method: method.to_owned(),
        params_json: params_json.to_owned(),
        target_uri: target_uri.to_owned(),
        audience_id: audience_id.to_owned(),
        route,
        dpop_token: dpop_token.to_owned(),
        nonce: nonce.to_owned(),
        created,
        expires,
        bindings_json,
    }
}

/// A request call: its id, and the ADR-MCPS-047 answer-leg handles, all five or none.
fn request_call(
    id_json: &str,
    prev_alg: Option<String>,
    prev_value: Option<String>,
    irr_alg: Option<String>,
    irr_value: Option<String>,
    request_state: Option<String>,
) -> Call {
    Call::Request {
        id_json: id_json.to_owned(),
        continuation: ContinuationArgs {
            prev_alg,
            prev_value,
            irr_alg,
            irr_value,
            request_state,
        },
    }
}

/// Sign an MCP request as an RFC 9421 + RFC 9530 message.
///
/// `dpop_token` is bound as an OAuth-DPoP artifact binding whose credential is the
/// covered `Authorization: Bearer` header. `created`/`expires` are Unix seconds. For an
/// ADR-MCPS-047 answer leg, the five `cont_*` handles bind this request to the
/// `InputRequiredResult` it answers; all five or none. `bindings_json` is the
/// provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook) as a
/// JSON array of specs; absent means DPoP only.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    seed, key_id, id_json, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires,
    cont_prev_alg=None, cont_prev_value=None, cont_irr_alg=None, cont_irr_value=None,
    cont_request_state=None, bindings_json=None,
))]
fn sign_request(
    seed: &[u8],
    key_id: &str,
    id_json: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let call = request_call(
        id_json,
        cont_prev_alg,
        cont_prev_value,
        cont_irr_alg,
        cont_irr_value,
        cont_request_state,
    );
    let args = sign_args(
        call,
        key_id,
        method,
        params_json,
        target_uri,
        audience_id,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    );
    mcp_re_binding_core::sign(args, seed)
        .map(PySignedRequest::from)
        .map_err(raise)
}

/// Sign an MCP request under NON-EXPORTING custody: the private key never enters the
/// SDK (ADR-MCPS-044 §Compliance).
///
/// `sign_callback` is the only thing held — `(preimage: bytes) -> bytes` — a KMS/HSM
/// client call in production, invoked synchronously while the GIL is held. The SDK
/// composes the RFC 9421 signature base, hands those exact bytes to the device, and
/// takes back the detached Ed25519 signature; it never sees key material.
///
/// The produced evidence is byte-identical to the software path for the same inputs —
/// the key has only moved behind the device. A device that cannot sign, or that
/// returns anything other than 64 signature bytes, fails closed as
/// `mcp-re.invalid_signature`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    sign_callback, key_id, id_json, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires,
    cont_prev_alg=None, cont_prev_value=None, cont_irr_alg=None, cont_irr_value=None,
    cont_request_state=None, bindings_json=None,
))]
fn sign_request_with_signer(
    py: Python<'_>,
    sign_callback: Py<PyAny>,
    key_id: &str,
    id_json: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let call = request_call(
        id_json,
        cont_prev_alg,
        cont_prev_value,
        cont_irr_alg,
        cont_irr_value,
        cont_request_state,
    );
    let args = sign_args(
        call,
        key_id,
        method,
        params_json,
        target_uri,
        audience_id,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    );
    mcp_re_binding_core::sign_with_device(args, device(py, &sign_callback))
        .map(PySignedRequest::from)
        .map_err(raise)
}

/// Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no
/// `id` — as an RFC 9421 + RFC 9530 message.
///
/// Signed by the ordinary request rules; only the JSON-RPC envelope differs. The
/// answer is a signed bodyless `202`, checked with [`verify_accepted_202`], not a
/// bodied reply. There are no continuation arguments: a message that receives no
/// result cannot be an ADR-MCPS-047 answer leg.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    seed, key_id, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires, bindings_json=None,
))]
fn sign_notification(
    seed: &[u8],
    key_id: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let args = sign_args(
        Call::Notification,
        key_id,
        method,
        params_json,
        target_uri,
        audience_id,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    );
    mcp_re_binding_core::sign(args, seed)
        .map(PySignedRequest::from)
        .map_err(raise)
}

/// Non-exporting-custody variant of [`sign_notification`]: the private key never
/// enters the SDK. Wire-identical to the software path.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    sign_callback, key_id, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires, bindings_json=None,
))]
fn sign_notification_with_signer(
    py: Python<'_>,
    sign_callback: Py<PyAny>,
    key_id: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let args = sign_args(
        Call::Notification,
        key_id,
        method,
        params_json,
        target_uri,
        audience_id,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    );
    mcp_re_binding_core::sign_with_device(args, device(py, &sign_callback))
        .map(PySignedRequest::from)
        .map_err(raise)
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
struct PyAcceptedResult {
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
struct PyVerifyResult {
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

/// The arguments both verification entry points share, in the order the Python API takes
/// them.
#[allow(clippy::too_many_arguments)]
fn verify_args(
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: &[u8],
    req_method: &str,
    req_target_uri: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    issuer: PinnedIssuer,
    verifier_audiences: Vec<String>,
    expected_audience_hash: &str,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_identifiers: Vec<String>,
    now: i64,
) -> VerifyArgs {
    VerifyArgs {
        response: HttpResponse {
            status,
            headers: resp_headers,
            body: resp_body.to_vec(),
        },
        request: HttpRequest {
            method: req_method.to_owned(),
            target_uri: req_target_uri.to_owned(),
            headers: req_headers,
            body: req_body.to_vec(),
        },
        issuer,
        verifier_audiences,
        expected_audience_hash: expected_audience_hash.to_owned(),
        accepted_epochs,
        max_clock_skew,
        revoked_identifiers,
        now,
    }
}

fn pinned(
    key_id: &str,
    pubkey_b64url: &str,
    role: &str,
    trust_domain: &str,
    subject: &str,
    retired_until: Option<i64>,
) -> PinnedIssuer {
    PinnedIssuer {
        key_id: key_id.to_owned(),
        pubkey_b64url: pubkey_b64url.to_owned(),
        role: role.to_owned(),
        trust_domain: trust_domain.to_owned(),
        subject: subject.to_owned(),
        retired_until,
    }
}

/// Verify the delegated-signed bodyless `202` a server returns for a one-way
/// notification, bound to the exact transmission this client sent.
///
/// The binding is INSTANCE-level (owner ruling C019b): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes its nonce. An acknowledgement captured for one transmission therefore does
/// not verify for a byte-identical retransmission.
///
/// Same trust inputs as `verify_response`: the ROOT ISSUER anchor, the audience scope,
/// the accepted trust epochs, and the client's static denylist. Anything unsigned,
/// direct-root-signed, revoked, stale-epoch, or bound to a different transmission fails
/// closed as a `ValueError` carrying the frozen wire code.
#[pyfunction]
#[pyo3(signature = (status, resp_headers, resp_body, req_method, req_target_uri, req_headers, req_body, issuer_key_id, issuer_pubkey_b64url, issuer_role, issuer_trust_domain, issuer_subject, verifier_audiences, expected_audience_hash, accepted_epochs, max_clock_skew, revoked_identifiers, now, issuer_retired_until = None))]
#[allow(clippy::too_many_arguments)]
fn verify_accepted_202(
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: &[u8],
    req_method: &str,
    req_target_uri: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    issuer_key_id: &str,
    issuer_pubkey_b64url: &str,
    issuer_role: &str,
    issuer_trust_domain: &str,
    issuer_subject: &str,
    verifier_audiences: Vec<String>,
    expected_audience_hash: &str,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_identifiers: Vec<String>,
    now: i64,
    issuer_retired_until: Option<i64>,
) -> PyResult<PyAcceptedResult> {
    let issuer = pinned(
        issuer_key_id,
        issuer_pubkey_b64url,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_retired_until,
    );
    let args = verify_args(
        status,
        resp_headers,
        resp_body,
        req_method,
        req_target_uri,
        req_headers,
        req_body,
        issuer,
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew,
        revoked_identifiers,
        now,
    );
    let accepted = mcp_re_binding_core::verify_accepted_202(args).map_err(raise)?;
    Ok(PyAcceptedResult {
        ok: true,
        server_keyid: accepted.server_keyid,
    })
}

/// Verify a delegated-required RFC 9421 response bound to the request the client
/// sent (ADR-MCPRE-052). Delegated-required is the ONLY response mode: the response
/// is signed by an in-memory delegated key whose inline compact-JWS credential must
/// chain to the trusted ROOT ISSUER (`issuer_*`) and be scoped to
/// `expected_audience_hash` at one of `accepted_epochs`. A response that is unsigned,
/// direct-root-signed, carries a revoked identifier, is scoped to a stale trust
/// epoch, or is bound to a different request fails closed (no downgrade).
///
/// `revoked_identifiers` is the client's static denylist (any mix of `delegated_kid`,
/// `issuer_kid`, or credential `jti`); an empty list is the explicit TTL-only posture.
///
/// The root is judged at `now`. `issuer_retired_until` (keyword, optional) declares it
/// RETIRED: its credentials verify while `now <= issuer_retired_until` and resolve to
/// untrusted after. Absent, the root is CURRENT. An empty or whitespace `issuer_*`
/// identity field is refused as a `ValueError` naming the field.
#[pyfunction]
#[pyo3(signature = (status, resp_headers, resp_body, req_method, req_target_uri, req_headers, req_body, issuer_key_id, issuer_pubkey_b64url, issuer_role, issuer_trust_domain, issuer_subject, verifier_audiences, expected_audience_hash, accepted_epochs, max_clock_skew, revoked_identifiers, now, issuer_retired_until = None))]
#[allow(clippy::too_many_arguments)]
fn verify_response(
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: &[u8],
    req_method: &str,
    req_target_uri: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    issuer_key_id: &str,
    issuer_pubkey_b64url: &str,
    issuer_role: &str,
    issuer_trust_domain: &str,
    issuer_subject: &str,
    verifier_audiences: Vec<String>,
    expected_audience_hash: &str,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_identifiers: Vec<String>,
    now: i64,
    issuer_retired_until: Option<i64>,
) -> PyResult<PyVerifyResult> {
    let issuer = pinned(
        issuer_key_id,
        issuer_pubkey_b64url,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_retired_until,
    );
    let args = verify_args(
        status,
        resp_headers,
        resp_body,
        req_method,
        req_target_uri,
        req_headers,
        req_body,
        issuer,
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew,
        revoked_identifiers,
        now,
    );
    mcp_re_binding_core::verify_response(args)
        .map(PyVerifyResult::from)
        .map_err(raise)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(profile_tag, m)?)?;
    m.add_function(wrap_pyfunction!(sign_preimage, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(sign_notification, m)?)?;
    m.add_function(wrap_pyfunction!(sign_notification_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;
    m.add_function(wrap_pyfunction!(verify_accepted_202, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PyVerifyResult>()?;
    m.add_class::<PyAcceptedResult>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::field_name;
    use super::request_call;
    use mcp_re_binding_core::BindingError;
    use mcp_re_binding_core::Call;
    use mcp_re_binding_core::IssuerField;

    #[test]
    fn an_issuer_field_is_named_by_its_python_keyword() {
        let named = [
            (IssuerField::KeyId, "issuer_key_id"),
            (IssuerField::Role, "issuer_role"),
            (IssuerField::TrustDomain, "issuer_trust_domain"),
            (IssuerField::Subject, "issuer_subject"),
        ];
        for (field, keyword) in named {
            assert_eq!(
                BindingError::EmptyIssuerField(field).message(field_name),
                format!("invalid issuer identity: {keyword} is empty")
            );
        }
    }

    #[test]
    fn the_five_continuation_keywords_reach_their_own_handles() {
        let call = request_call(
            "7",
            Some("a".into()),
            Some("b".into()),
            Some("c".into()),
            Some("d".into()),
            Some("e".into()),
        );
        let Call::Request {
            id_json,
            continuation,
        } = call
        else {
            panic!("a request call");
        };
        assert_eq!(id_json, "7");
        assert_eq!(continuation.prev_alg.as_deref(), Some("a"));
        assert_eq!(continuation.prev_value.as_deref(), Some("b"));
        assert_eq!(continuation.irr_alg.as_deref(), Some("c"));
        assert_eq!(continuation.irr_value.as_deref(), Some("d"));
        assert_eq!(continuation.request_state.as_deref(), Some("e"));
    }
}
