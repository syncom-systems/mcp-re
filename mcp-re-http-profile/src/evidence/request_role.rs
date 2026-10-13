// SPDX-License-Identifier: Apache-2.0
//! The REQUEST-role evidence handle: derived, never assembled.

use serde::Serialize;

use super::role::labeled_digest_value;
use super::role::EvidenceRole;
use super::RequestEvidenceDigest;
use crate::error::HttpProfileError;
use crate::ids::EVIDENCE_DIGEST_ALG;
use crate::ids::REQUEST_LABEL;
use crate::message::HttpRequest;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verify::floor::signature_input::parse_signature_input_for;

/// The request-role handle over a request's exact RFC 9421 signature base (v0.11 grill
/// C.1/E-5). It commits to the body digest, method, target URI, media type, key id,
/// signature parameters and covered-component set, and serves MRTR continuation, audit
/// correlation and response binding.
///
/// Sealed: the representation is private and [`from_signature_base`](Self::from_signature_base)
/// is the only producer, so holding one means its value IS the request-role labeled digest
/// of some signature base. A response-role handle is a different type, so a slot typed for
/// this role cannot hold one, whether or not that slot compares anything. A handle read
/// from a peer is a [`RequestEvidenceDigest`] claim and is checked with
/// [`matches`](Self::matches).
///
/// Serializes to the wire's split form, `{digest_alg, digest_value}`.
///
/// Code outside this crate cannot write the value in:
///
/// ```compile_fail
/// use mcp_re_http_profile::RequestRoleEvidence;
/// let _ = RequestRoleEvidence { digest_value: String::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRoleEvidence {
    digest_value: String,
}

impl RequestRoleEvidence {
    /// Derive the handle from the exact request signature-base bytes.
    pub fn from_signature_base(base: &[u8]) -> Self {
        RequestRoleEvidence {
            digest_value: labeled_digest_value(EvidenceRole::Request, base),
        }
    }

    /// The handle OF a signed request: the request-role digest over the signature base its
    /// own `mcp-re` `Signature-Input` member describes.
    ///
    /// The one derivation of a request's handle. A bound response is verified against the
    /// handle of the concrete request it answers, and a bodyless 202 covers the same
    /// handle, so the two response shapes carry one binding: a handle is a function of the
    /// request, never a second operand a caller supplies beside it.
    ///
    /// It identifies one transmission: the base's `@signature-params` carry the nonce, so
    /// a byte-identical retransmission derives a different handle. It reaches that
    /// identity without covering the request's `Signature` value, which RFC 9421 §7.3.7
    /// makes NOT RECOMMENDED, and without reading the textual `Signature-Input` value.
    ///
    /// This is a derivation, not a verification. It rebuilds the base and digests it; it
    /// checks no signature, resolves no trust and enforces no required-component set,
    /// which are [`crate::verify::floor_request`]'s. It admits any parseable covered set,
    /// and because the base's `@signature-params` line names that set, a request declaring
    /// a set no producer signs derives a handle no producer emits, so the difference fails
    /// closed at the comparison.
    ///
    /// Fails closed when the request carries no `Signature-Input`, no `mcp-re` member in it,
    /// a member that does not parse, or a covered set the base cannot be built over: in
    /// each case there is no signature base, and therefore no handle.
    pub(crate) fn of_signed_request(request: &HttpRequest) -> Result<Self, HttpProfileError> {
        let parsed =
            parse_signature_input_for(&request.headers, REQUEST_LABEL, "request signature-input")?;
        let base = signature_base(
            &parsed.components,
            &parsed.params,
            &SourceMessage::Request(request),
        )?;
        Ok(Self::from_signature_base(&base))
    }

    /// The digest algorithm, always the profile's.
    pub fn digest_alg(&self) -> &'static str {
        EVIDENCE_DIGEST_ALG
    }

    /// The unpadded base64url digest value.
    pub fn digest_value(&self) -> &str {
        &self.digest_value
    }

    /// The wire form of this handle, for a block that carries it.
    pub fn to_digest(&self) -> RequestEvidenceDigest {
        RequestEvidenceDigest {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: self.digest_value.clone(),
        }
    }

    /// Whether `claim` names this handle: the same algorithm and value.
    pub fn matches(&self, claim: &RequestEvidenceDigest) -> bool {
        claim.digest_alg == EVIDENCE_DIGEST_ALG && claim.digest_value == self.digest_value
    }
}

impl Serialize for RequestRoleEvidence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_digest().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_split_form_and_deterministic() {
        let a = RequestRoleEvidence::from_signature_base(b"base bytes");
        assert_eq!(a, RequestRoleEvidence::from_signature_base(b"base bytes"));
        assert_eq!(a.digest_alg(), "sha256");
        assert!(a.to_digest().is_well_formed(), "{a:?}");
        assert_ne!(a, RequestRoleEvidence::from_signature_base(b"base bytez"));
    }

    #[test]
    fn it_is_the_request_role_digest_and_no_other() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert!(a
            .to_digest()
            .matches_labeled(EvidenceRole::Request, b"base"));
        assert!(!a
            .to_digest()
            .matches_labeled(EvidenceRole::Response, b"base"));
    }

    #[test]
    fn matches_its_own_claim_only() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert!(a.matches(&a.to_digest()));
        let response_role = RequestEvidenceDigest::over_labeled(EvidenceRole::Response, b"base");
        assert!(!a.matches(&response_role));
        let other_alg = RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            ..a.to_digest()
        };
        assert!(!a.matches(&other_alg));
    }

    fn signed_request() -> (HttpRequest, RequestRoleEvidence) {
        let mut request = HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://mcp.example.com/mcp".to_owned(),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
        };
        let evidence = crate::sign::sign_request(
            &mut request,
            &mcp_re_core::SigningKey::from_seed_bytes(&[11u8; 32]),
            "client-key-1",
            1_700_000_000,
            1_700_000_300,
            &mcp_re_test_paths::unique_test_nonce(),
        )
        .expect("the fixture request signs");
        (request, evidence)
    }

    #[test]
    fn a_derived_handle_agrees_with_the_signers_handle() {
        let (request, signed) = signed_request();
        assert_eq!(
            RequestRoleEvidence::of_signed_request(&request)
                .expect("the signed request has a handle"),
            signed
        );
    }

    #[test]
    fn a_request_differing_in_a_covered_component_derives_a_different_handle() {
        let (request, signed) = signed_request();
        let mut other = request.clone();
        other.target_uri = "https://mcp.example.com/other".to_owned();
        assert_ne!(
            RequestRoleEvidence::of_signed_request(&other).ok(),
            Some(signed)
        );
    }

    #[test]
    fn a_thin_covered_set_cannot_reproduce_a_signed_handle() {
        let (request, signed) = signed_request();
        let mut thin = request.clone();
        for (name, value) in &mut thin.headers {
            if !name.eq_ignore_ascii_case("signature-input") {
                continue;
            }
            let open = value.find('(').expect("covered set opens");
            let close = value.find(')').expect("covered set closes");
            value.replace_range(open + 1..close, "");
        }
        assert_ne!(
            RequestRoleEvidence::of_signed_request(&thin).ok(),
            Some(signed)
        );
    }

    #[test]
    fn a_request_with_no_signature_input_has_no_handle() {
        let request = HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://mcp.example.com/mcp".to_owned(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        };
        assert!(RequestRoleEvidence::of_signed_request(&request).is_err());
    }

    /// The wire bytes are the split form the unsealed type serialized to.
    #[test]
    fn serializes_to_the_split_wire_form() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({ "digest_alg": "sha256", "digest_value": a.digest_value() })
        );
    }
}
