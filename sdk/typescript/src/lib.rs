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
//! the signing inputs, the typed device failure, the root anchor, the verify preamble and
//! the verdict are that crate's, shared with the PyO3 binding.
//!
//! A refusal crosses into JavaScript typed, never as prose to parse: a thrown error's
//! `code` is the frozen `mcp-re.*` token for a wire refusal, [`SIGNING_DEVICE_FAILURE`]
//! when the signing device could not sign (with what the device threw as its `cause`),
//! and `"InvalidArg"` for any other refusal of the caller's arguments.

#[macro_use]
mod entry_points;

mod core_facts;
mod refusal;
mod results;
mod sign_inputs;
mod verify_inputs;

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::Function;
use napi_derive::napi;

use mcp_re_binding_core::Call;
use mcp_re_binding_core::ContinuationArgs;
use mcp_re_binding_core::IssuerField;
use refusal::device;
use refusal::raise;
use refusal::raise_signing;
use refusal::Refusal;
use refusal::INVALID_ARG;
use results::AcceptedResultJs;
use results::SignedRequestJs;
use results::VerifyResultJs;
use sign_inputs::request_call;
use sign_inputs::Signing;
use sign_inputs::Window;
use verify_inputs::Answer;
use verify_inputs::Issuer;
use verify_inputs::Transmitted;
use verify_inputs::Trust;
use verify_inputs::Verification;

/// An issuer field by the key the TypeScript API takes it as.
fn field_name(field: IssuerField) -> &'static str {
    match field {
        IssuerField::KeyId => "issuerKeyId",
        IssuerField::Role => "issuerRole",
        IssuerField::TrustDomain => "issuerTrustDomain",
        IssuerField::Subject => "issuerSubject",
    }
}

/// The largest whole number of seconds a JS number carries exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_SECONDS: f64 = 9_007_199_254_740_991.0;

fn is_whole(v: f64) -> bool {
    v.is_finite() && v.fract() == 0.0
}

fn is_safe_magnitude(v: f64) -> bool {
    v.abs() <= MAX_SAFE_SECONDS
}

/// A JS number as whole seconds. A saturating `as i64` would turn Infinity into an
/// unbounded expiry or skew and NaN into 0, so a non-finite, fractional or
/// beyond-`Number.MAX_SAFE_INTEGER` value is refused instead.
fn whole_seconds(v: f64, what: &str) -> Result<i64, Refusal> {
    if is_whole(v) && is_safe_magnitude(v) {
        return Ok(v as i64);
    }
    Err(napi::Error::new(
        INVALID_ARG.to_owned(),
        format!("{what} must be a whole number of seconds, got {v}"),
    ))
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

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature — the primitive a `SigningDevice` (the HSM/KMS stand-in) is built on.
///
/// This is the same operation the software signing path performs internally, so a
/// device-delegated signature is byte-identical to the in-process one.
#[napi]
pub fn sign_preimage(seed: Buffer, preimage: Buffer) -> Result<Buffer, Refusal> {
    mcp_re_binding_core::sign_preimage(seed.as_ref(), preimage.as_ref())
        .map(Buffer::from)
        .map_err(raise)
}

request_entry! {
    #[doc = " Sign an MCP request as an RFC 9421 + RFC 9530 message."]
    #[doc = ""]
    #[doc = " For an ADR-MCPS-047 answer leg, the five `cont*` handles bind this request to the"]
    #[doc = " `InputRequiredResult` it answers; all five or none. `bindingsJson` is the"]
    #[doc = " provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook) as a"]
    #[doc = " JSON array of specs; absent means DPoP only."]
    fn sign_request(seed: Buffer, args) {
        mcp_re_binding_core::sign(args, seed.as_ref())
            .map(SignedRequestJs::from)
            .map_err(raise)
    }
}

request_entry! {
    #[doc = " Sign an MCP request under NON-EXPORTING custody: the private key never enters the"]
    #[doc = " SDK (ADR-MCPS-044 §Compliance)."]
    #[doc = ""]
    #[doc = " `signCallback` is the only thing held — `(preimage: Buffer) => Buffer` — a KMS/HSM"]
    #[doc = " client call in production, invoked synchronously on the Node main thread. The SDK"]
    #[doc = " composes the RFC 9421 signature base, hands those exact bytes to the device, and"]
    #[doc = " takes back the detached Ed25519 signature; it never sees key material."]
    #[doc = ""]
    #[doc = " The produced evidence is byte-identical to the software path for the same inputs —"]
    #[doc = " the key has only moved behind the device. A device that cannot sign, or that"]
    #[doc = " returns anything other than 64 signature bytes, fails closed as"]
    #[doc = " `mcp-re.invalid_signature`."]
    fn sign_request_with_signer(sign_callback: Function<Buffer, Buffer>, args) {
        mcp_re_binding_core::sign_with_device(args, device(&sign_callback))
            .map(SignedRequestJs::from)
            .map_err(raise_signing)
    }
}

notification_entry! {
    #[doc = " Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no"]
    #[doc = " `id` — as an RFC 9421 + RFC 9530 message."]
    #[doc = ""]
    #[doc = " Signed by the ordinary request rules; only the JSON-RPC envelope differs. The answer"]
    #[doc = " is a signed bodyless `202`, checked with `verifyAccepted202`, not a bodied reply."]
    #[doc = " There are no continuation arguments: a message that receives no result cannot be an"]
    #[doc = " ADR-MCPS-047 answer leg."]
    fn sign_notification(seed: Buffer, args) {
        mcp_re_binding_core::sign(args, seed.as_ref())
            .map(SignedRequestJs::from)
            .map_err(raise)
    }
}

notification_entry! {
    #[doc = " Non-exporting-custody variant of `signNotification`: the private key never enters"]
    #[doc = " the SDK. Wire-identical to the software path."]
    fn sign_notification_with_signer(sign_callback: Function<Buffer, Buffer>, args) {
        mcp_re_binding_core::sign_with_device(args, device(&sign_callback))
            .map(SignedRequestJs::from)
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
    #[doc = " Same trust inputs as `verifyResponse`: the root issuer anchor, the audience scope,"]
    #[doc = " the accepted trust epochs, and the client's static denylist."]
    fn verify_accepted_202(args) -> AcceptedResultJs {
        let accepted = mcp_re_binding_core::verify_accepted_202(args).map_err(raise)?;
        Ok(AcceptedResultJs::from(accepted))
    }
}

verify_entry! {
    #[doc = " Verify a delegated-required (the ONLY mode) RFC 9421 response bound to the request the"]
    #[doc = " client sent: the credential chains to the root issuer judged at `now` (a root retired"]
    #[doc = " with `issuerRetiredUntil` is trusted through that deadline) and is scoped to"]
    #[doc = " `expectedAudienceHash` at one of `acceptedEpochs`. Anything unsigned, direct-root,"]
    #[doc = " revoked, stale-epoch or wrongly bound throws. `revokedIdentifiers` is the client's"]
    #[doc = " static denylist; an empty list is the explicit TTL-only posture."]
    fn verify_response(args) -> VerifyResultJs {
        mcp_re_binding_core::verify_response(args)
            .map(VerifyResultJs::from)
            .map_err(raise)
    }
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
