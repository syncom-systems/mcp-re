// SPDX-License-Identifier: Apache-2.0
//! The MRTR continuation carried in the request evidence block: three role-labeled
//! handles, built from the open leg's evidence and verified against what the correlation
//! store retained.

use serde::Deserialize;
use serde::Serialize;

use crate::error::HttpProfileError;
use crate::evidence::EvidenceRole;
use crate::evidence::RequestEvidenceDigest;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// MRTR continuation carried in the request evidence block. Three standards-
/// derived handles (ADR-MCPRE-050 §Resolved-owner ruling 7): the derivation and
/// verification land in MCPRE-97; the schema is defined here so the block is
/// complete. `requestState` stays opaque but is now digest-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpContinuation {
    /// Continuation kind; `"mcp-mrt"` (kept MCP-specific).
    #[serde(rename = "type")]
    pub continuation_type: String,
    /// SHA-256 over the previous client request's RFC 9421 signature base.
    pub previous_request_evidence: RequestEvidenceDigest,
    /// SHA-256 over the verified `InputRequiredResult` response signature base.
    pub input_required_response_evidence: RequestEvidenceDigest,
    /// SHA-256 over the opaque `requestState` bytes — opaque-but-digest-bound.
    pub request_state_digest: RequestEvidenceDigest,
}

/// The `mcp-mrt` continuation type token (kept MCP-specific).
#[allow(clippy::redundant_static_lifetimes)]
#[cfg_attr(feature = "verify", verus_verify)]
pub const CONTINUATION_TYPE_MCP_MRT: &'static str = "mcp-mrt";

impl HttpContinuation {
    /// Build the three-handle continuation (MCPRE-97) from the mandated inputs:
    /// the previous client request's signature base, the verified
    /// `InputRequiredResult` response's signature base, and the opaque
    /// `requestState` bytes. All three are hashed — `requestState` stays opaque
    /// (never interpreted) but is now digest-bound.
    pub fn build(
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Self {
        HttpContinuation {
            continuation_type: CONTINUATION_TYPE_MCP_MRT.to_owned(),
            previous_request_evidence: RequestEvidenceDigest::over_labeled(
                EvidenceRole::Request,
                previous_request_base,
            ),
            input_required_response_evidence: RequestEvidenceDigest::over_labeled(
                EvidenceRole::Response,
                input_required_response_base,
            ),
            request_state_digest: RequestEvidenceDigest::over_labeled(
                EvidenceRole::RequestState,
                request_state,
            ),
        }
    }

    /// Build the continuation from digest HANDLES the caller already holds — the
    /// previous client request's evidence digest (`RequestRoleEvidence` over its
    /// signature base) and the verified `InputRequiredResult` response's evidence
    /// digest — plus the opaque `requestState` bytes (hashed here). This is the
    /// answer-leg client's path (ADR-MCPS-047): after verifying an
    /// `InputRequiredResult` it already has both evidence digests (its own sent-
    /// request handle and the response's `response_signature_base_digest`) and never
    /// needs to retain the raw signature bases. The handles are not checked here: the result
    /// equals [`HttpContinuation::build`] only over role-labeled digests; `verify` refuses others.
    pub fn from_handles(
        previous_request_evidence: RequestEvidenceDigest,
        input_required_response_evidence: RequestEvidenceDigest,
        request_state: &[u8],
    ) -> Self {
        HttpContinuation {
            continuation_type: CONTINUATION_TYPE_MCP_MRT.to_owned(),
            previous_request_evidence,
            input_required_response_evidence,
            request_state_digest: RequestEvidenceDigest::over_labeled(
                EvidenceRole::RequestState,
                request_state,
            ),
        }
    }

    /// The continuation's own shape, before any binding: the `mcp-mrt` type, and three
    /// handles shaped as derived handles are. One failing it binds to no retained handle,
    /// so [`verify`](Self::verify) refuses it whatever the store holds.
    pub fn validate_shape(&self) -> Result<(), HttpProfileError> {
        if self.continuation_type != CONTINUATION_TYPE_MCP_MRT {
            return Err(HttpProfileError::MalformedEvidence("continuation type"));
        }
        let handles = [
            &self.previous_request_evidence,
            &self.input_required_response_evidence,
            &self.request_state_digest,
        ];
        if !handles.iter().all(|h| h.is_well_formed()) {
            return Err(HttpProfileError::MalformedEvidence("continuation handle"));
        }
        Ok(())
    }

    /// Verify the continuation against the evidence handles the correlation store retained
    /// at the open leg, and the exact `requestState` bytes the client re-presents. A wrong
    /// type is malformed; a handle that is not the retained one is a continuation-binding
    /// failure (a splice across the continuation boundary, or a tampered `requestState`).
    // ADR-MCPRE-059 WP3 — the continuation role-labeled BINDING DISCIPLINE contract. An
    // accepted continuation's two evidence handles ARE the retained handles (minted under
    // their own role labels at the open leg) and its state handle is the modeled labeled
    // digest of the presented `requestState`. Role SEPARATION (distinct labels never
    // collide) is `boundary.crypto_primitives`' and is absent from the model.
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures
            out matches Ok(()) ==> {
                &&& self.previous_request_evidence.digest_alg@ == previous_request.digest_alg@
                &&& self.previous_request_evidence.digest_value@ == previous_request.digest_value@
                &&& self.input_required_response_evidence.digest_alg@
                        == input_required_response.digest_alg@
                &&& self.input_required_response_evidence.digest_value@
                        == input_required_response.digest_value@
                &&& self.request_state_digest.digest_alg@ == crate::ids::EVIDENCE_DIGEST_ALG@
                &&& self.request_state_digest.digest_value@
                        == crate::verus_std_specs::labeled_digest(
                            crate::ids::EVIDENCE_LABEL_REQUEST_STATE@, request_state@)
            },
    ))]
    pub fn verify(
        &self,
        previous_request: &RequestEvidenceDigest,
        input_required_response: &RequestEvidenceDigest,
        request_state: &[u8],
    ) -> Result<(), HttpProfileError> {
        if self.continuation_type != CONTINUATION_TYPE_MCP_MRT {
            return Err(HttpProfileError::MalformedEvidence("continuation type"));
        }
        // Each handle is compared IN ITS SLOT: the retained previous-request handle was
        // minted under the request role and the response handle under the response role, so
        // a handle presented in the wrong slot differs from the retained one.
        if !self.previous_request_evidence.same_handle(previous_request) {
            return Err(HttpProfileError::ContinuationBindingFailed);
        }
        if !self
            .input_required_response_evidence
            .same_handle(input_required_response)
        {
            return Err(HttpProfileError::ContinuationBindingFailed);
        }
        if !self
            .request_state_digest
            .matches_labeled(EvidenceRole::RequestState, request_state)
        {
            return Err(HttpProfileError::ContinuationBindingFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREV_BASE: &[u8] = b"previous-request-signature-base";
    const IRR_BASE: &[u8] = b"input-required-response-signature-base";
    const REQ_STATE: &[u8] = b"opaque-request-state-blob";

    /// Verify `c` against the handles the open leg would have retained for these bases.
    fn verify_over(
        c: &HttpContinuation,
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Result<(), HttpProfileError> {
        c.verify(
            &RequestEvidenceDigest::over_labeled(EvidenceRole::Request, previous_request_base),
            &RequestEvidenceDigest::over_labeled(
                EvidenceRole::Response,
                input_required_response_base,
            ),
            request_state,
        )
    }

    fn built() -> HttpContinuation {
        HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE)
    }

    fn binding_failed(c: &HttpContinuation, prev: &[u8], irr: &[u8], state: &[u8]) {
        assert_eq!(
            verify_over(c, prev, irr, state).unwrap_err(),
            HttpProfileError::ContinuationBindingFailed
        );
    }

    #[test]
    fn continuation_round_trips_and_verifies() {
        let c = built();
        let json = serde_json::to_string(&c).unwrap();
        let back: HttpContinuation = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        verify_over(&c, PREV_BASE, IRR_BASE, REQ_STATE).expect("binds its inputs");
        // The type token is the MCP-specific mcp-mrt.
        assert_eq!(c.continuation_type, "mcp-mrt");
    }

    #[test]
    fn tampered_request_state_breaks_the_digest() {
        // requestState stays opaque (never interpreted) but IS digest-bound.
        let c = built();
        binding_failed(&c, PREV_BASE, IRR_BASE, b"opaque-request-state-TAMPERED");
        assert_eq!(
            HttpProfileError::ContinuationBindingFailed.wire_code(),
            "mcp-re.continuation_binding_failed"
        );
    }

    #[test]
    fn splice_across_continuation_boundary_fails() {
        // A continuation presented against a DIFFERENT previous request (a
        // splice) must not verify.
        let c = built();
        binding_failed(&c, b"some-other-request-base", IRR_BASE, REQ_STATE);
        // Likewise a different input-required response.
        binding_failed(&c, PREV_BASE, b"other-irr-base", REQ_STATE);
    }

    /// The signer refuses each of these as a malformed handle before signing; the verifier
    /// keeps its own classification and refuses each as a binding failure.
    #[test]
    fn a_malformed_handle_is_a_binding_failure_at_the_verifier() {
        let corruptions: [fn(&mut HttpContinuation); 4] = [
            |c| c.previous_request_evidence.digest_value.truncate(10),
            |c| c.input_required_response_evidence.digest_alg = "sha-256".into(),
            |c| c.request_state_digest.digest_value.push('='),
            |c| {
                c.previous_request_evidence = RequestEvidenceDigest {
                    digest_alg: "none".into(),
                    digest_value: String::new(),
                }
            },
        ];
        for corrupt in corruptions {
            let mut c = built();
            corrupt(&mut c);
            assert!(c.validate_shape().is_err(), "{c:?}");
            let err = verify_over(&c, PREV_BASE, IRR_BASE, REQ_STATE).unwrap_err();
            assert_eq!(err, HttpProfileError::ContinuationBindingFailed);
            assert_eq!(err.wire_code(), "mcp-re.continuation_binding_failed");
        }
    }

    #[test]
    fn wrong_continuation_type_is_malformed() {
        let mut c = built();
        c.continuation_type = "some-other-continuation".into();
        assert_eq!(
            verify_over(&c, PREV_BASE, IRR_BASE, REQ_STATE).unwrap_err(),
            HttpProfileError::MalformedEvidence("continuation type")
        );
    }

    #[test]
    fn from_handles_over_role_labeled_digests_is_wire_identical_to_build() {
        assert_eq!(
            HttpContinuation::from_handles(
                RequestEvidenceDigest::over_labeled(EvidenceRole::Request, PREV_BASE),
                RequestEvidenceDigest::over_labeled(EvidenceRole::Response, IRR_BASE),
                REQ_STATE
            ),
            built()
        );
    }

    #[test]
    fn a_wrong_role_handle_from_handles_is_refused_by_verify() {
        let c = HttpContinuation::from_handles(
            RequestEvidenceDigest::over_labeled(EvidenceRole::Response, PREV_BASE),
            RequestEvidenceDigest::over_labeled(EvidenceRole::Response, IRR_BASE),
            REQ_STATE,
        );
        binding_failed(&c, PREV_BASE, IRR_BASE, REQ_STATE);
    }
}
