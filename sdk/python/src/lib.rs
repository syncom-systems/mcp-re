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
//! signing inputs, the typed device failure, the root anchor, the verify preamble and the
//! verdict are that crate's, shared with the N-API binding.
//!
//! A refusal crosses into Python typed, never as prose to parse: [`WireRefusal`] carries
//! the frozen `mcp-re.*` token in `.wire_code`, [`SigningDeviceFailure`] says the device
//! could not sign and has no wire code, with the device's own exception as `__cause__`,
//! and any other refusal of the caller's arguments is a plain `ValueError`.

#[macro_use]
mod entry_points;

mod core_facts;
mod refusal;
mod results;
mod sign_inputs;
mod verify_inputs;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcp_re_binding_core::Call;
use mcp_re_binding_core::ContinuationArgs;
use mcp_re_binding_core::IssuerField;
use refusal::device;
use refusal::raise;
use refusal::raise_signing;
use refusal::SigningDeviceFailure;
use refusal::WireRefusal;
use results::PyAcceptedResult;
use results::PySignedRequest;
use results::PyVerifyResult;
use sign_inputs::request_call;
use sign_inputs::Signing;
use sign_inputs::Window;
use verify_inputs::Answer;
use verify_inputs::Issuer;
use verify_inputs::Transmitted;
use verify_inputs::Trust;
use verify_inputs::Verification;

/// An issuer field by the keyword the Python API takes it as.
fn field_name(field: IssuerField) -> &'static str {
    match field {
        IssuerField::KeyId => "issuer_key_id",
        IssuerField::Role => "issuer_role",
        IssuerField::TrustDomain => "issuer_trust_domain",
        IssuerField::Subject => "issuer_subject",
    }
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

request_entry! {
    #[doc = " Sign an MCP request as an RFC 9421 + RFC 9530 message."]
    #[doc = ""]
    #[doc = " `dpop_token` is bound as an OAuth-DPoP artifact binding whose credential is the"]
    #[doc = " covered `Authorization: Bearer` header. `created`/`expires` are Unix seconds. For an"]
    #[doc = " ADR-MCPS-047 answer leg, the five `cont_*` handles bind this request to the"]
    #[doc = " `InputRequiredResult` it answers; all five or none. `bindings_json` is the"]
    #[doc = " provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook) as a"]
    #[doc = " JSON array of specs; absent means DPoP only."]
    fn sign_request(_py, seed: &[u8], args) {
        mcp_re_binding_core::sign(args, seed)
            .map(PySignedRequest::from)
            .map_err(raise)
    }
}

request_entry! {
    #[doc = " Sign an MCP request under NON-EXPORTING custody: the private key never enters the"]
    #[doc = " SDK (ADR-MCPS-044 §Compliance)."]
    #[doc = ""]
    #[doc = " `sign_callback` is the only thing held — `(preimage: bytes) -> bytes` — a KMS/HSM"]
    #[doc = " client call in production, invoked synchronously while the GIL is held. The SDK"]
    #[doc = " composes the RFC 9421 signature base, hands those exact bytes to the device, and"]
    #[doc = " takes back the detached Ed25519 signature; it never sees key material."]
    #[doc = ""]
    #[doc = " The produced evidence is byte-identical to the software path for the same inputs —"]
    #[doc = " the key has only moved behind the device. A device that cannot sign, or that"]
    #[doc = " returns anything other than 64 signature bytes, fails closed as"]
    #[doc = " `mcp-re.invalid_signature`."]
    fn sign_request_with_signer(py, sign_callback: Py<PyAny>, args) {
        mcp_re_binding_core::sign_with_device(args, device(py, &sign_callback))
            .map(PySignedRequest::from)
            .map_err(raise_signing)
    }
}

notification_entry! {
    #[doc = " Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no"]
    #[doc = " `id` — as an RFC 9421 + RFC 9530 message."]
    #[doc = ""]
    #[doc = " Signed by the ordinary request rules; only the JSON-RPC envelope differs. The"]
    #[doc = " answer is a signed bodyless `202`, checked with [`verify_accepted_202`], not a"]
    #[doc = " bodied reply. There are no continuation arguments: a message that receives no"]
    #[doc = " result cannot be an ADR-MCPS-047 answer leg."]
    fn sign_notification(_py, seed: &[u8], args) {
        mcp_re_binding_core::sign(args, seed)
            .map(PySignedRequest::from)
            .map_err(raise)
    }
}

notification_entry! {
    #[doc = " Non-exporting-custody variant of [`sign_notification`]: the private key never"]
    #[doc = " enters the SDK. Wire-identical to the software path."]
    fn sign_notification_with_signer(py, sign_callback: Py<PyAny>, args) {
        mcp_re_binding_core::sign_with_device(args, device(py, &sign_callback))
            .map(PySignedRequest::from)
            .map_err(raise_signing)
    }
}

verify_entry! {
    #[doc = " Verify the delegated-signed bodyless `202` a server returns for a one-way"]
    #[doc = " notification, bound to the exact transmission this client sent."]
    #[doc = ""]
    #[doc = " The binding is INSTANCE-level (owner ruling C019b): the acknowledgement covers"]
    #[doc = " `mcp-re-request-evidence`, the digest of the request's own signature base, which"]
    #[doc = " includes its nonce. An acknowledgement captured for one transmission therefore does"]
    #[doc = " not verify for a byte-identical retransmission."]
    #[doc = ""]
    #[doc = " Same trust inputs as `verify_response`: the ROOT ISSUER anchor, the audience scope,"]
    #[doc = " the accepted trust epochs, and the client's static denylist. Anything unsigned,"]
    #[doc = " direct-root-signed, revoked, stale-epoch, or bound to a different transmission fails"]
    #[doc = " closed as a `WireRefusal` carrying the frozen wire code."]
    fn verify_accepted_202(args) -> PyAcceptedResult {
        let accepted = mcp_re_binding_core::verify_accepted_202(args).map_err(raise)?;
        Ok(PyAcceptedResult::from(accepted))
    }
}

verify_entry! {
    #[doc = " Verify a delegated-required RFC 9421 response bound to the request the client"]
    #[doc = " sent (ADR-MCPRE-052). Delegated-required is the ONLY response mode: the response"]
    #[doc = " is signed by an in-memory delegated key whose inline compact-JWS credential must"]
    #[doc = " chain to the trusted ROOT ISSUER (`issuer_*`) and be scoped to"]
    #[doc = " `expected_audience_hash` at one of `accepted_epochs`. A response that is unsigned,"]
    #[doc = " direct-root-signed, carries a revoked identifier, is scoped to a stale trust"]
    #[doc = " epoch, or is bound to a different request fails closed (no downgrade)."]
    #[doc = ""]
    #[doc = " `revoked_identifiers` is the client's static denylist (any mix of `delegated_kid`,"]
    #[doc = " `issuer_kid`, or credential `jti`); an empty list is the explicit TTL-only posture."]
    #[doc = ""]
    #[doc = " The root is judged at `now`. `issuer_retired_until` (keyword, optional) declares it"]
    #[doc = " RETIRED: its credentials verify while `now <= issuer_retired_until` and resolve to"]
    #[doc = " untrusted after. Absent, the root is CURRENT. An empty or whitespace `issuer_*`"]
    #[doc = " identity field is refused as a `ValueError` naming the field."]
    fn verify_response(args) -> PyVerifyResult {
        mcp_re_binding_core::verify_response(args)
            .map(PyVerifyResult::from)
            .map_err(raise)
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    core_facts::register(m)?;
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
    m.add("WireRefusal", m.py().get_type::<WireRefusal>())?;
    m.add(
        "SigningDeviceFailure",
        m.py().get_type::<SigningDeviceFailure>(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::field_name;
    use mcp_re_binding_core::BindingError;
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
}
