// SPDX-License-Identifier: Apache-2.0
//! The response-side body evidence block.

use serde::Deserialize;
use serde::Serialize;

use super::actor::ActorIdentity;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidenceDigest;

/// The response-side body evidence block (`se.syncom/mcp-re.http.response`,
/// MCPRE-101). Carries the resolved server signer identity and the request
/// evidence handle this response is bound to. Like the request block it rides in
/// the JSON-RPC body `_meta` and is protected by the covered `content-digest`.
///
/// `request_evidence` is explicit MCP semantic defense-in-depth ON TOP of the
/// cryptographic `;req` binding: `verify_response_full` compares it against the
/// recomputed request signature-base digest from the verified request context,
/// and a mismatch is `request_binding_mismatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseEvidenceBlock {
    /// The signed profile id; cross-checked against `PROFILE_TAG`.
    pub profile: String,
    /// The server's resolved signer identity (role, trust domain, subject,
    /// keyid). Cross-checked against the keyid the response signature verified
    /// under.
    pub server_signer: ActorIdentity,
    /// The inline delegation credential (compact JOSE/JWS), when the response is
    /// signed by a delegated key (ADR-MCPRE-052 §2). A sibling of `server_signer`,
    /// protected by the covered `content-digest` exactly as `server_signer` is.
    /// Absent on directly root-signed responses (backward-compatible: pre-052
    /// vectors omit it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_delegation: Option<String>,
    /// The request evidence handle (`SHA-256` over the request signature base)
    /// this response asserts it is answering.
    pub request_evidence: RequestEvidenceDigest,
}

impl HttpResponseEvidenceBlock {
    /// Checks the profile tag only: the signer and request-handle relations are decided in `verify`.
    pub fn validate(&self, expected_profile: &str) -> Result<(), HttpProfileError> {
        if self.profile != expected_profile {
            return Err(HttpProfileError::UnknownProfileTag);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceRole;
    use crate::ids::PROFILE_TAG;

    fn response_block() -> HttpResponseEvidenceBlock {
        HttpResponseEvidenceBlock {
            profile: PROFILE_TAG.into(),
            server_signer: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: "server-key-1".into(),
            },
            server_delegation: None,
            request_evidence: RequestEvidenceDigest::over_labeled(EvidenceRole::Request, b"base"),
        }
    }

    #[test]
    fn response_block_round_trips_and_validates() {
        let b = response_block();
        let json = serde_json::to_string(&b).unwrap();
        let back: HttpResponseEvidenceBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        b.validate(PROFILE_TAG).expect("valid");
    }

    #[test]
    fn response_block_unknown_field_fails_closed() {
        let mut v = serde_json::to_value(response_block()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("surprise".into(), serde_json::json!(1));
        let err = serde_json::from_value::<HttpResponseEvidenceBlock>(v).unwrap_err();
        assert!(err.to_string().contains("unknown field `surprise`"));
    }

    #[test]
    fn response_block_foreign_profile_fails_closed() {
        let mut b = response_block();
        b.profile = "someone-elses-profile".into();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::UnknownProfileTag
        );
    }
}
