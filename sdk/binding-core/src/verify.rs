// SPDX-License-Identifier: Apache-2.0
//! Verification of a delegated-required answer (ADR-MCPRE-052).
//!
//! Delegated-required is the only response mode: the answer is signed by an in-memory
//! delegated key whose inline compact-JWS credential must chain to the pinned root issuer
//! and be scoped to the expected audience at an accepted epoch. Anything unsigned,
//! direct-root-signed, revoked, stale-epoch or bound to a different request is refused.

use mcp_re_client_core::verify_delegated_accepted_202;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ResponseExpectation;

use crate::verdict::VerifiedParts;
use crate::BindingError;
use crate::Verdict;
use crate::VerifyArgs;

/// The enforcement boundary authenticated and accepted the notification this client sent.
///
/// NOT that the action completed, that the inner application observed it, or that anything
/// was done about it: a verified acknowledgement of `notifications/cancelled` does not mean
/// anything was cancelled. `server_keyid` is the delegated key that signed it, never the
/// root, which stays off the request path (ADR-MCPRE-052).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    pub server_keyid: String,
}

/// Verify a bodied answer bound to the request the client sent.
pub fn verify_response(args: VerifyArgs) -> Result<Verdict, BindingError> {
    args.judge(|j| {
        let expectation = ResponseExpectation::new(j.request);
        let verified =
            verify_delegated_response(j.response, j.trust, &expectation, j.policy, j.now)?;
        // `result.requestState` only if this is an InputRequiredResult. The verified product
        // derives it from the body verification covered, and refuses a reply that declares
        // itself non-terminal without a usable state, or whose `resultType` is outside the
        // set MCP 2026-07-28 defines.
        let request_state = verified.continuation_state()?;
        let evidence = verified.verified();
        let digest = evidence.response_signature_base_digest();
        Ok(Verdict::project(VerifiedParts {
            server_keyid: &evidence.accepted_signer().identity.keyid,
            outcome: verified.outcome(),
            evidence_bound: evidence.is_bound(),
            resp_evidence_digest_alg: digest.digest_alg(),
            resp_evidence_digest_value: digest.digest_value(),
            request_state,
        }))
    })
}

/// Verify the bodyless `202` a server returns for a one-way notification, bound to the
/// exact transmission this client sent.
///
/// The binding is instance-level (owner ruling C019b): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes its nonce, so an acknowledgement captured for one transmission does not verify
/// for a byte-identical retransmission.
pub fn verify_accepted_202(args: VerifyArgs) -> Result<Acceptance, BindingError> {
    args.judge(|j| {
        let actor =
            verify_delegated_accepted_202(j.response, &j.request, j.trust, j.policy, j.now)?;
        Ok(Acceptance {
            server_keyid: actor.identity.keyid,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::verify_accepted_202;
    use super::verify_response;
    use crate::BindingError;
    use crate::PinnedIssuer;
    use crate::VerifyArgs;
    use mcp_re_client_core::HttpRequest;
    use mcp_re_client_core::HttpResponse;
    use mcp_re_core::SigningKey;

    fn args(status: u16) -> VerifyArgs {
        VerifyArgs {
            response: HttpResponse {
                status,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            },
            request: HttpRequest {
                method: "POST".into(),
                target_uri: "https://example.com/mcp".into(),
                headers: Vec::new(),
                body: b"{}".to_vec(),
            },
            issuer: PinnedIssuer {
                key_id: "root-1".into(),
                pubkey_b64url: SigningKey::from_seed_bytes(&[7u8; 32])
                    .public_key()
                    .to_b64url(),
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server-1".into(),
                retired_until: None,
            },
            verifier_audiences: vec!["aud".into()],
            expected_audience_hash: "h".into(),
            accepted_epochs: vec!["e1".into()],
            max_clock_skew: 30,
            revoked_identifiers: Vec::new(),
            now: 1_000,
        }
    }

    #[test]
    fn an_unsigned_answer_is_a_wire_refusal_on_both_entry_points() {
        let Err(BindingError::Wire(bodied)) = verify_response(args(200)) else {
            panic!("an unsigned answer is refused under a wire code");
        };
        let Err(BindingError::Wire(accepted)) = verify_accepted_202(args(202)) else {
            panic!("an unsigned acknowledgement is refused under a wire code");
        };
        assert!(bodied.starts_with("mcp-re.") && accepted.starts_with("mcp-re."));
    }
}
