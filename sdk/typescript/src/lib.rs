// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-sdk-core` — the napi-rs native addon for the MCP-RE TypeScript SDK,
//! exposing the audited `mcp-re-client-core` RFC 9421 signing / verification seam
//! (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest; the
//! signature rides in the HTTP headers, not a JSON-RPC `_meta` block.
//!
//! Two custody classes are exposed (ADR-MCPS-044 §Compliance): `signRequest` takes a
//! raw seed (software custody), and `signRequestWithSigner` takes only a sign
//! callback, so the private key never enters the SDK (non-exporting custody).
//!
//! This file marshals JavaScript values into `mcp-re-binding-core` and its results back;
//! the signing inputs, the device check, the root anchor, the verify preamble and the
//! verdict are that crate's, shared with the PyO3 binding.

mod core_facts;

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::Function;
use napi_derive::napi;

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

/// An issuer field by the key the TypeScript API takes it as.
fn field_name(field: IssuerField) -> &'static str {
    match field {
        IssuerField::KeyId => "issuerKeyId",
        IssuerField::Role => "issuerRole",
        IssuerField::TrustDomain => "issuerTrustDomain",
        IssuerField::Subject => "issuerSubject",
    }
}

/// A binding refusal as the error the TypeScript SDK throws.
fn raise(e: BindingError) -> napi::Error {
    napi::Error::from_reason(e.message(field_name))
}

/// A JS number as whole seconds. A saturating `as i64` would turn Infinity into an
/// unbounded expiry or skew and NaN into 0, so a non-finite, fractional or
/// beyond-`Number.MAX_SAFE_INTEGER` value is refused instead.
fn whole_seconds(v: f64, what: &str) -> napi::Result<i64> {
    if !(v.is_finite() && v.fract() == 0.0 && v.abs() <= 9_007_199_254_740_991.0) {
        return Err(napi::Error::from_reason(format!(
            "{what} must be a whole number of seconds, got {v}"
        )));
    }
    Ok(v as i64)
}

/// A device callback as the core's device seam: the signature bytes, or `None` when the
/// callback threw.
fn device<'a, 'scope: 'a>(
    sign_callback: &'a Function<'scope, Buffer, Buffer>,
) -> impl FnOnce(&[u8]) -> Option<Vec<u8>> + 'a {
    move |preimage: &[u8]| {
        let out = sign_callback.call(Buffer::from(preimage.to_vec())).ok()?;
        Some(out.to_vec())
    }
}

/// One HTTP header (name/value pair) on the RFC 9421 request/response.
#[napi(object)]
pub struct HttpHeader {
    pub key: String,
    pub value: String,
}

fn to_pairs(headers: Vec<HttpHeader>) -> Vec<(String, String)> {
    headers.into_iter().map(|h| (h.key, h.value)).collect()
}

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

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature — the primitive a `SigningDevice` (the HSM/KMS stand-in) is built on.
///
/// This is the same operation the software signing path performs internally, so a
/// device-delegated signature is byte-identical to the in-process one.
#[napi]
pub fn sign_preimage(seed: Buffer, preimage: Buffer) -> napi::Result<Buffer> {
    mcp_re_binding_core::sign_preimage(seed.as_ref(), preimage.as_ref())
        .map(Buffer::from)
        .map_err(raise)
}

/// The arguments every signing entry point shares, in the order the TypeScript API takes
/// them.
#[allow(clippy::too_many_arguments)]
fn sign_args(
    call: Call,
    key_id: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<SignArgs> {
    Ok(SignArgs {
        call,
        key_id,
        method,
        params_json,
        target_uri,
        audience_id,
        route,
        dpop_token,
        nonce,
        created: whole_seconds(created, "created")?,
        expires: whole_seconds(expires, "expires")?,
        bindings_json,
    })
}

/// A request call: its id, and the ADR-MCPS-047 answer-leg handles, all five or none.
fn request_call(
    id_json: String,
    prev_alg: Option<String>,
    prev_value: Option<String>,
    irr_alg: Option<String>,
    irr_value: Option<String>,
    request_state: Option<String>,
) -> Call {
    Call::Request {
        id_json,
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
/// For an ADR-MCPS-047 answer leg, the five `cont*` handles bind this request to the
/// `InputRequiredResult` it answers; all five or none. `bindingsJson` is the
/// provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook) as a
/// JSON array of specs; absent means DPoP only.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    seed: Buffer,
    key_id: String,
    id_json: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
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
    )?;
    mcp_re_binding_core::sign(args, seed.as_ref())
        .map(SignedRequestJs::from)
        .map_err(raise)
}

/// Sign an MCP request under NON-EXPORTING custody: the private key never enters the
/// SDK (ADR-MCPS-044 §Compliance).
///
/// `signCallback` is the only thing held — `(preimage: Buffer) => Buffer` — a KMS/HSM
/// client call in production, invoked synchronously on the Node main thread. The SDK
/// composes the RFC 9421 signature base, hands those exact bytes to the device, and
/// takes back the detached Ed25519 signature; it never sees key material.
///
/// The produced evidence is byte-identical to the software path for the same inputs —
/// the key has only moved behind the device. A device that cannot sign, or that
/// returns anything other than 64 signature bytes, fails closed as
/// `mcp-re.invalid_signature`.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_request_with_signer(
    sign_callback: Function<Buffer, Buffer>,
    key_id: String,
    id_json: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
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
    )?;
    mcp_re_binding_core::sign_with_device(args, device(&sign_callback))
        .map(SignedRequestJs::from)
        .map_err(raise)
}

/// Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no
/// `id` — as an RFC 9421 + RFC 9530 message.
///
/// Signed by the ordinary request rules; only the JSON-RPC envelope differs. The answer
/// is a signed bodyless `202`, checked with `verifyAccepted202`, not a bodied reply.
/// There are no continuation arguments: a message that receives no result cannot be an
/// ADR-MCPS-047 answer leg.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_notification(
    seed: Buffer,
    key_id: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
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
    )?;
    mcp_re_binding_core::sign(args, seed.as_ref())
        .map(SignedRequestJs::from)
        .map_err(raise)
}

/// Non-exporting-custody variant of `signNotification`: the private key never enters
/// the SDK. Wire-identical to the software path.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_notification_with_signer(
    sign_callback: Function<Buffer, Buffer>,
    key_id: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
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
    )?;
    mcp_re_binding_core::sign_with_device(args, device(&sign_callback))
        .map(SignedRequestJs::from)
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
#[napi(object)]
pub struct AcceptedResultJs {
    pub ok: bool,
    /// The delegated key id that signed the acknowledgement — never the root, which
    /// stays off the request path (ADR-MCPRE-052).
    pub server_keyid: String,
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

/// The arguments both verification entry points share, in the order the TypeScript API
/// takes them.
#[allow(clippy::too_many_arguments)]
fn verify_args(
    status: u16,
    resp_headers: Vec<HttpHeader>,
    resp_body: Buffer,
    req_method: String,
    req_target_uri: String,
    req_headers: Vec<HttpHeader>,
    req_body: Buffer,
    issuer: PinnedIssuer,
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: f64,
    revoked_identifiers: Vec<String>,
    now: f64,
) -> napi::Result<VerifyArgs> {
    Ok(VerifyArgs {
        response: HttpResponse {
            status,
            headers: to_pairs(resp_headers),
            body: resp_body.to_vec(),
        },
        request: HttpRequest {
            method: req_method,
            target_uri: req_target_uri,
            headers: to_pairs(req_headers),
            body: req_body.to_vec(),
        },
        issuer,
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew: whole_seconds(max_clock_skew, "maxClockSkew")?,
        revoked_identifiers,
        now: whole_seconds(now, "now")?,
    })
}

fn pinned(
    key_id: String,
    pubkey_b64url: String,
    role: String,
    trust_domain: String,
    subject: String,
    retired_until: Option<f64>,
) -> napi::Result<PinnedIssuer> {
    Ok(PinnedIssuer {
        key_id,
        pubkey_b64url,
        role,
        trust_domain,
        subject,
        retired_until: retired_until
            .map(|t| whole_seconds(t, "issuerRetiredUntil"))
            .transpose()?,
    })
}

/// Verify the delegated-signed bodyless `202` a server returns for a one-way
/// notification, bound to the exact transmission this client sent.
///
/// The binding is INSTANCE-level (owner ruling C019b): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes its nonce. An acknowledgement captured for one transmission therefore does
/// not verify for a byte-identical retransmission.
///
/// Same trust inputs as `verifyResponse`: the root issuer anchor, the audience scope,
/// the accepted trust epochs, and the client's static denylist.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn verify_accepted_202(
    status: u16,
    resp_headers: Vec<HttpHeader>,
    resp_body: Buffer,
    req_method: String,
    req_target_uri: String,
    req_headers: Vec<HttpHeader>,
    req_body: Buffer,
    issuer_key_id: String,
    issuer_pubkey_b64url: String,
    issuer_role: String,
    issuer_trust_domain: String,
    issuer_subject: String,
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: f64,
    revoked_identifiers: Vec<String>,
    now: f64,
    issuer_retired_until: Option<f64>,
) -> napi::Result<AcceptedResultJs> {
    let issuer = pinned(
        issuer_key_id,
        issuer_pubkey_b64url,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_retired_until,
    )?;
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
    )?;
    let accepted = mcp_re_binding_core::verify_accepted_202(args).map_err(raise)?;
    Ok(AcceptedResultJs {
        ok: true,
        server_keyid: accepted.server_keyid,
    })
}

/// Verify a delegated-required (the ONLY mode) RFC 9421 response bound to the request the
/// client sent: the credential chains to the root issuer judged at `now` (a root retired
/// with `issuerRetiredUntil` is trusted through that deadline) and is scoped to
/// `expectedAudienceHash` at one of `acceptedEpochs`. Anything unsigned, direct-root,
/// revoked, stale-epoch or wrongly bound throws. `revokedIdentifiers` is the client's
/// static denylist; an empty list is the explicit TTL-only posture.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn verify_response(
    status: u16,
    resp_headers: Vec<HttpHeader>,
    resp_body: Buffer,
    req_method: String,
    req_target_uri: String,
    req_headers: Vec<HttpHeader>,
    req_body: Buffer,
    issuer_key_id: String,
    issuer_pubkey_b64url: String,
    issuer_role: String,
    issuer_trust_domain: String,
    issuer_subject: String,
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: f64,
    revoked_identifiers: Vec<String>,
    now: f64,
    issuer_retired_until: Option<f64>,
) -> napi::Result<VerifyResultJs> {
    let issuer = pinned(
        issuer_key_id,
        issuer_pubkey_b64url,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_retired_until,
    )?;
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
    )?;
    mcp_re_binding_core::verify_response(args)
        .map(VerifyResultJs::from)
        .map_err(raise)
}

#[cfg(test)]
mod tests {
    use super::field_name;
    use super::whole_seconds;
    use mcp_re_binding_core::BindingError;
    use mcp_re_binding_core::IssuerField;

    #[test]
    fn a_time_that_is_not_whole_seconds_is_refused() {
        for bad in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.5,
            9_007_199_254_740_992.0,
            -9_007_199_254_740_992.0,
        ] {
            assert!(whole_seconds(bad, "now").is_err(), "{bad} must be refused");
        }
        assert_eq!(
            whole_seconds(9_007_199_254_740_991.0, "now").ok(),
            Some(9_007_199_254_740_991)
        );
        assert_eq!(whole_seconds(-3.0, "now").ok(), Some(-3));
    }

    #[test]
    fn an_issuer_field_is_named_by_its_typescript_key() {
        let named = [
            (IssuerField::KeyId, "issuerKeyId"),
            (IssuerField::Role, "issuerRole"),
            (IssuerField::TrustDomain, "issuerTrustDomain"),
            (IssuerField::Subject, "issuerSubject"),
        ];
        for (field, key) in named {
            assert_eq!(
                BindingError::EmptyIssuerField(field).message(field_name),
                format!("invalid issuer identity: {key} is empty")
            );
        }
    }
}
