// SPDX-License-Identifier: Apache-2.0
//! The request-side body evidence block and its structural validation.

use serde::Deserialize;
use serde::Serialize;

use super::artifact_binding::ArtifactBinding;
use super::artifact_binding::ArtifactType;
use super::artifact_binding::BindingType;
use super::audience::AudienceTuple;
use super::continuation::HttpContinuation;
use crate::error::HttpProfileError;
use crate::ids::MAX_ADMISSION_ASSERTION_LEN;
use crate::pdp_decision::MAX_AUTHORIZATION_DECISION_LEN;

/// The request-side body evidence block (`se.syncom/mcp-re.http.request`).
/// `profile`, `audience`, and a non-empty `artifact_bindings` are required;
/// `continuation` is present only on a continuation request (like the native
/// envelope), so it is optional in presence but part of the schema.
///
/// Public fields, deliberately: the continuation-unbypassability proof reads
/// `continuation` as a field, and a seal would replace that proved read with a getter
/// assumption. The boundary is enforced at signing instead — no profile signer signs a
/// body carrying a block that fails [`validate`](Self::validate) or whose continuation
/// fails [`HttpContinuation::validate_shape`], nor binds a response to such a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestEvidenceBlock {
    /// The signed profile id; cross-checked against the RFC 9421 `tag`.
    pub profile: String,
    /// The audience tuple (richer than `@target-uri`).
    pub audience: AudienceTuple,
    /// Required, non-empty. Generalizes the draft-02 `authorization_binding`.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// MRTR continuation (present only on continuation requests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HttpContinuation>,
    /// The §7 admission binding: which admission the call acts under (MCPRE-433).
    /// Present only where a deployment enforces admission; optional so pre-433
    /// vectors and admission-free deployments are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<crate::admission::AdmissionBinding>,
    /// The inline admission assertion (compact JOSE/JWS) the binding commits to
    /// (MCPRE-493).
    ///
    /// A sibling of `admission`, protected by the covered `content-digest` exactly
    /// as it is — the same shape the response block uses for `server_delegation`,
    /// and for the same reason: an evidence artifact the verifier must have in hand
    /// travels with the message rather than being fetched. It rides in the BODY, not
    /// a header, because E-3 admits a new MCP-RE header field only where the message
    /// shape leaves no alternative (a bodyless 202), and a request has a body.
    ///
    /// Without it the binding is uncheckable: the binding commits to a digest of the
    /// admitted-state the authority attested, so a verifier holding only the binding
    /// can compare that digest against nothing. `validate` therefore requires the two
    /// to appear together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_assertion: Option<String>,
    /// The inline authorization decision (compact JOSE/JWS) an external authority issued
    /// for this call — ADR-MCPRE-065 Slice 2.
    ///
    /// A sibling of the `pdp-decision` / `opaque-digest` entry in
    /// [`artifact_bindings`](Self::artifact_bindings), exactly as `admission_assertion` is a
    /// sibling of `admission`, and protected the same way: by the covered `content-digest`.
    /// It rides in the BODY because E-3 admits a new MCP-RE header field only where the
    /// message shape leaves no alternative, and a request has a body.
    ///
    /// Carried rather than referenced. A deployment that had to resolve a decision reference
    /// would be unable to serve whenever its authority was unreachable, and the proposition
    /// this evidence supports would then silently include *the PDP is online*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_decision: Option<String>,
}

impl HttpRequestEvidenceBlock {
    /// Structural validation, fail-closed: profile tag matches, at least one
    /// artifact binding, every binding structurally valid.
    pub fn validate(&self, expected_profile: &str) -> Result<(), HttpProfileError> {
        if self.profile != expected_profile {
            return Err(HttpProfileError::UnknownProfileTag);
        }
        if self.artifact_bindings.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "empty artifact_bindings",
            ));
        }
        // Admission is both halves or neither. A binding alone commits to a digest
        // of state no one here can see, so it cannot be checked; an assertion alone
        // is an authority's statement bound to no call. Either shape would verify
        // structurally and enforce nothing, which is worse than being absent —
        // absent is at least legible as "this deployment does not do admission".
        match (&self.admission, &self.admission_assertion) {
            (None, None) => {}
            (Some(_), Some(jws)) => {
                if jws.len() > MAX_ADMISSION_ASSERTION_LEN {
                    // Bounded before parsing: an assertion is a compact JWS over a
                    // small claim set, and an unbounded value is a parse/memory
                    // surface reachable pre-trust.
                    return Err(HttpProfileError::MalformedEvidence(
                        "admission assertion size",
                    ));
                }
            }
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "admission binding and assertion must appear together",
                ))
            }
        }
        self.validate_authorization_decision()?;
        Ok(())
    }

    /// The structural rules for an inline authorization decision (ADR-MCPRE-065 Slice 2).
    ///
    /// Three of them, and each closes a way the pairing could be ambiguous:
    ///
    /// 1. **Both halves or neither.** A binding alone commits to the digest of a document
    ///    nobody supplied, so nothing can check it; a decision alone is an authority's
    ///    statement bound to no call. Either shape verifies structurally and enforces
    ///    nothing — worse than absent, which is at least legible as *this deployment does
    ///    not do authorization*.
    /// 2. **Exactly one applicable binding.** Two `pdp-decision` / `opaque-digest` entries
    ///    would leave the verifier choosing which one the document is supposed to match,
    ///    and a caller supplying both a matching and a non-matching one would pass whichever
    ///    check happened to be written first.
    /// 3. **A reference binding never satisfies it.** `pdp-decision` / `reference-digest` is
    ///    the LINKAGE form: it names an external decision MCP-RE does not authenticate or
    ///    interpret. Letting it stand in for the evidence form would let a call claim an
    ///    enforcement decision it never carried.
    ///
    /// Size is bounded before any of it: the value is read from an unauthenticated peer and
    /// an unbounded one is a parse and memory surface reachable pre-trust.
    fn validate_authorization_decision(&self) -> Result<(), HttpProfileError> {
        let applicable = self
            .artifact_bindings
            .iter()
            .filter(|b| {
                b.artifact_type() == ArtifactType::PdpDecision
                    && b.binding_type() == BindingType::OpaqueDigest
            })
            .count();
        match (&self.authorization_decision, applicable) {
            (None, _) => Ok(()),
            (Some(jws), _) if jws.len() > MAX_AUTHORIZATION_DECISION_LEN => Err(
                HttpProfileError::MalformedEvidence("authorization decision size"),
            ),
            (Some(_), 1) => Ok(()),
            (Some(_), 0) => Err(HttpProfileError::MalformedEvidence(
                "authorization decision without a pdp-decision opaque-digest binding",
            )),
            (Some(_), _) => Err(HttpProfileError::MalformedEvidence(
                "more than one pdp-decision opaque-digest binding",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PROFILE_TAG;

    fn dpop_binding() -> ArtifactBinding {
        ArtifactBinding::opaque_from_digest(
            ArtifactType::OauthDpop,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect("a legal binding")
    }

    fn block() -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: AudienceTuple {
                audience_id: "did:example:server".into(),
                target_uri: "https://mcp.example.com/mcp".into(),
                route: None,
            },
            artifact_bindings: vec![dpop_binding()],
            continuation: None,
            admission: None,
            admission_assertion: None,
            authorization_decision: None,
        }
    }

    fn refused(b: &HttpRequestEvidenceBlock, reason: &'static str) {
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::MalformedEvidence(reason)
        );
    }

    #[test]
    fn block_round_trips() {
        let b = block();
        let json = serde_json::to_string(&b).unwrap();
        let back: HttpRequestEvidenceBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        b.validate(PROFILE_TAG).expect("valid");
    }

    #[test]
    fn unknown_field_fails_closed() {
        let json = r#"{"profile":"mcp-re-http-v1","audience":{"audience_id":"a","target_uri":"u"},"artifact_bindings":[],"surprise":1}"#;
        let err = serde_json::from_str::<HttpRequestEvidenceBlock>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `surprise`"),
            "deny_unknown_fields must reject stray members"
        );
    }

    #[test]
    fn empty_artifact_bindings_fails_closed() {
        let mut b = block();
        b.artifact_bindings.clear();
        refused(&b, "empty artifact_bindings");
    }

    #[test]
    fn foreign_profile_fails_closed() {
        let mut b = block();
        b.profile = "someone-elses-profile".into();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::UnknownProfileTag
        );
    }

    /// A request block carrying a malformed binding does not parse, so no block holds one.
    #[test]
    fn a_block_carrying_a_malformed_binding_does_not_parse() {
        let mut json = serde_json::to_value(block()).expect("serializes");
        json["artifact_bindings"][0]["digest_value"] = "A".into();
        assert!(serde_json::from_value::<HttpRequestEvidenceBlock>(json).is_err());
    }

    #[test]
    fn artifact_binding_carries_only_digest_and_reference_never_token_bytes() {
        // A DPoP artifact is expressed as a digest, not the token. The serialized
        // form has no field able to hold raw token/secret bytes.
        let json = serde_json::to_string(&dpop_binding()).unwrap();
        assert!(json.contains("digest_value"));
        for forbidden in ["token", "jwt", "secret", "private", "access_token"] {
            assert!(
                !json.contains(forbidden),
                "no raw-secret field: {forbidden}"
            );
        }
    }

    /// A binding entry whose fields disagree with its binding form is refused at parse.
    fn binding_entry_is_refused(entry: serde_json::Value) {
        assert!(serde_json::from_value::<ArtifactBinding>(entry).is_err());
    }

    #[test]
    fn opaque_binding_with_reference_fields_fails_closed() {
        binding_entry_is_refused(serde_json::json!({
            "artifact_type": "oauth-dpop",
            "binding_type": "opaque-digest",
            "digest_alg": "sha256",
            "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "reference_value": "grant-123",
        }));
    }

    #[test]
    fn reference_binding_missing_fields_fails_closed() {
        binding_entry_is_refused(serde_json::json!({
            "artifact_type": "oauth-rar",
            "binding_type": "reference-digest",
            "digest_alg": "sha256",
            "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "authorization_system_id": "authz",
        }));
    }

    fn admission_binding() -> crate::admission::AdmissionBinding {
        crate::admission::AdmissionBinding {
            binding_type: BindingType::OpaqueDigest,
            admission_id: "w".into(),
            generation: 1,
            digest_alg: crate::ids::EVIDENCE_DIGEST_ALG.into(),
            digest_value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }

    fn pdp_reference_binding() -> ArtifactBinding {
        ArtifactBinding::reference(
            ArtifactType::PdpDecision,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sys",
            "scheme",
            "handle",
        )
        .expect("a legal binding")
    }

    fn pdp_opaque_binding(credential: &[u8]) -> ArtifactBinding {
        ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, credential)
    }

    /// Set a bounded inline value at its limit (accepted) and one past it (refused with `reason`).
    fn bounded_before_parsing(
        mut b: HttpRequestEvidenceBlock,
        set: fn(&mut HttpRequestEvidenceBlock, String),
        limit: usize,
        reason: &'static str,
    ) {
        set(&mut b, "a".repeat(limit));
        b.validate(PROFILE_TAG).expect("at the bound");
        set(&mut b, "a".repeat(limit + 1));
        refused(&b, reason);
    }

    #[test]
    fn admission_binding_and_assertion_must_appear_together() {
        let together = "admission binding and assertion must appear together";
        let mut b = block();
        b.admission = Some(admission_binding());
        refused(&b, together);
        let mut b = block();
        b.admission_assertion = Some("a.b.c".into());
        refused(&b, together);
        b.admission = Some(admission_binding());
        b.validate(PROFILE_TAG).expect("both halves validate");
    }

    #[test]
    fn admission_assertion_is_bounded_before_parsing() {
        let mut b = block();
        b.admission = Some(admission_binding());
        bounded_before_parsing(
            b,
            |b, v| b.admission_assertion = Some(v),
            MAX_ADMISSION_ASSERTION_LEN,
            "admission assertion size",
        );
    }

    #[test]
    fn authorization_decision_without_an_evidence_binding_fails_closed() {
        let missing = "authorization decision without a pdp-decision opaque-digest binding";
        let mut b = block();
        b.authorization_decision = Some("a.b.c".into());
        refused(&b, missing);
        b.artifact_bindings.push(pdp_reference_binding());
        refused(&b, missing);
    }

    #[test]
    fn authorization_decision_with_two_evidence_bindings_fails_closed() {
        let mut b = block();
        b.authorization_decision = Some("a.b.c".into());
        b.artifact_bindings.push(pdp_opaque_binding(b"one"));
        b.validate(PROFILE_TAG).expect("exactly one binding");
        b.artifact_bindings.push(pdp_opaque_binding(b"two"));
        refused(&b, "more than one pdp-decision opaque-digest binding");
    }

    #[test]
    fn authorization_decision_is_bounded_before_parsing() {
        let mut b = block();
        b.artifact_bindings.push(pdp_opaque_binding(b"one"));
        bounded_before_parsing(
            b,
            |b, v| b.authorization_decision = Some(v),
            MAX_AUTHORIZATION_DECISION_LEN,
            "authorization decision size",
        );
    }
}
