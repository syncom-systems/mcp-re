// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPRE-065 acceptance fixtures: the authority's key and trust file, and the decision matrix.

use super::*;

/// The seed of the authorization authority's signing key for the acceptance deployment.
const ACCEPTANCE_PDP_SEED: u8 = 91;

/// The authorization authority's signing key for the acceptance deployment.
fn acceptance_pdp_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[ACCEPTANCE_PDP_SEED; 32])
}

const ACCEPTANCE_PDP_KID: &str = "pdp-acceptance-1";

/// A trust document enrolling the request signer AND one authorization authority.
///
/// Written here rather than by `write_material` because the enrolment is part of what is
/// being measured: the request-signer slot and the authorization-issuer slot are different
/// authorities, and a fixture that always carried both would prove neither.
pub(super) fn acceptance_trust_file(
    material: &Material,
    enrol_authority: bool,
) -> std::path::PathBuf {
    let mut entries = vec![json!({
        "signer": SUBJECT_A,
        "key_id": SIGNER_A_KEY_ID,
        "public_key": signer_a_key().public_key().to_b64url(),
        "slots": ["request"],
    })];
    if enrol_authority {
        entries.push(json!({
            "signer": "did:example:pdp",
            "key_id": ACCEPTANCE_PDP_KID,
            "public_key": acceptance_pdp_key().public_key().to_b64url(),
            "slots": ["authorization-issuer"],
        }));
    }
    let path = tmp(&format!(
        "acceptance-trust-{}.json",
        u8::from(enrol_authority)
    ));
    std::fs::write(&path, serde_json::to_vec(&entries).expect("serialize")).expect("write");
    let _ = material;
    path
}

/// The tool every decorated request calls, and every decision is about.
pub(super) const DECIDED_TOOL: &str = "echo";

/// A decision about this deployment's client, issued by the enrolled authority.
///
/// Every knob a matrix row turns is a field: the outcome, the decided operation, the
/// subject, the issuing key (to make the authority untrusted), and the validity window (to
/// make it stale).
pub(super) struct DecisionSpec<'a> {
    pub(super) outcome: PdpDecisionOutcome,
    operation: &'a str,
    pub(super) subject: &'a str,
    /// The seed of the issuing key: the enrolled authority's, or another to make it untrusted.
    key_seed: u8,
    pub(super) kid: &'a str,
    issued_at: i64,
}

impl<'a> DecisionSpec<'a> {
    /// A Permit from the enrolled authority, about this actor and this action, issued at `now`.
    pub(super) fn permit(now: i64) -> Self {
        DecisionSpec {
            outcome: PdpDecisionOutcome::Permit,
            operation: "tools/call",
            subject: SUBJECT_A,
            key_seed: ACCEPTANCE_PDP_SEED,
            kid: ACCEPTANCE_PDP_KID,
            issued_at: now,
        }
    }

    /// The signed decision.
    pub(super) fn issue(&self) -> String {
        let key = SigningKey::from_seed_bytes(&[self.key_seed; 32]);
        let claims = PdpDecisionClaims {
            iss: "did:example:pdp".into(),
            issuer_kid: self.kid.into(),
            iat: self.issued_at,
            nbf: self.issued_at - 5,
            exp: self.issued_at + 3600,
            jti: "acceptance-decision-1".into(),
            aud: Audience::One(AUDIENCE.into()),
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: TRUST_DOMAIN.into(),
                subject: self.subject.into(),
            },
            // The decorated request signs `tools/call` naming the tool `DECIDED_TOOL`, so the
            // action coordinate the PEP reads from the SIGNED BODY is that operation and that
            // target. A decision must be about exactly that.
            mcp_re_decided_operation: self.operation.into(),
            mcp_re_decided_target: Some(DECIDED_TOOL.into()),
            mcp_re_decision: self.outcome,
            mcp_re_policy_version: "acceptance-v1".into(),
        };
        issue_authorization_decision(&claims, |input| {
            mcp_re_core::b64url_decode(&key.sign(input))
                .map_err(|_| mcp_re_http_profile::HttpProfileError::InvalidSignature)
        })
        .expect("the enrolled authority issues")
    }
}

/// Every row that must be refused. Each names the flaw it introduces, and the deployment is
/// identical across all of them — only the decision changes. `None` carries no decision.
pub(super) fn refusal_matrix(now: i64) -> Vec<(&'static str, Option<String>)> {
    let decided = |spec: DecisionSpec| Some(spec.issue());
    vec![
        (
            "authz-deny",
            decided(DecisionSpec {
                outcome: PdpDecisionOutcome::Deny,
                ..DecisionSpec::permit(now)
            }),
        ),
        // A configured profile refuses an undecorated request. §7.1: a deployment that
        // configured an authority has left the not-configured posture.
        ("authz-absent", None),
        (
            "authz-other-action",
            decided(DecisionSpec {
                operation: "prompts/get",
                ..DecisionSpec::permit(now)
            }),
        ),
        (
            "authz-other-actor",
            decided(DecisionSpec {
                subject: "did:example:someone-else",
                ..DecisionSpec::permit(now)
            }),
        ),
        // A well-formed decision from an authority this trust document does not enrol.
        (
            "authz-untrusted-issuer",
            decided(DecisionSpec {
                key_seed: 92,
                kid: "pdp-not-enrolled",
                ..DecisionSpec::permit(now)
            }),
        ),
        // Inside its own validity window, and older than this enforcement point accepts.
        (
            "authz-stale",
            decided(DecisionSpec {
                issued_at: now - 5_000,
                ..DecisionSpec::permit(now)
            }),
        ),
    ]
}
