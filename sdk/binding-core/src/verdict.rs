// SPDX-License-Identifier: Apache-2.0
//! The result a caller sees for one verified delegated response.
//!
//! The execution contract travels as the receipt stated it: a member the receipt did not
//! state stays absent, because collapsing silence into "not executed" is the read that
//! makes a post-dispatch refusal look retry-safe.

use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::ExecutionContract;

/// A verified delegated response.
///
/// Every value here was verified: the credential chained to the trusted root and the
/// delegated signature covered the message. That does NOT mean the request succeeded.
/// `outcome` is `"success"` for an accepted answer and `"rejection"` for a verified
/// rejection receipt, genuine evidence that is not an acceptance; a caller decides
/// acceptance on `outcome == "success"`. `wire_code` is a rejection's frozen reason.
/// `bound` is whether a rejection is bound to this client's request; a success is bound by
/// construction.
///
/// The ADR-MCPRE-058 §10 members (`execution_status`, `retry_safety`,
/// `continuation_status`, `retention_status`) are absent on success and on a receipt that
/// stated nothing; an absent `execution_status` is not `"not_executed"`.
///
/// The response evidence digest is the `input_required_response_evidence` handle an
/// ADR-MCPS-047 answer leg binds to. `request_state` is `result.requestState` iff the
/// audited classifier reads the reply as an `InputRequiredResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub server_keyid: String,
    pub outcome: &'static str,
    pub wire_code: Option<String>,
    pub bound: bool,
    pub execution_status: Option<String>,
    pub retry_safety: Option<String>,
    pub continuation_status: Option<String>,
    pub retention_status: Option<String>,
    pub resp_evidence_digest_alg: String,
    pub resp_evidence_digest_value: String,
    pub request_state: Option<String>,
}

/// The verified parts of a response a [`Verdict`] is projected from.
pub(crate) struct VerifiedParts<'a> {
    pub(crate) server_keyid: &'a str,
    pub(crate) outcome: &'a DelegatedOutcome,
    pub(crate) evidence_bound: bool,
    pub(crate) resp_evidence_digest_alg: &'a str,
    pub(crate) resp_evidence_digest_value: &'a str,
    pub(crate) request_state: Option<String>,
}

impl Verdict {
    pub(crate) fn project(parts: VerifiedParts<'_>) -> Verdict {
        let (outcome, wire_code, bound, execution) = match parts.outcome {
            DelegatedOutcome::Success => ("success", None, true, ExecutionContract::default()),
            DelegatedOutcome::Rejection {
                wire_code,
                execution,
            } => (
                "rejection",
                wire_code.clone(),
                parts.evidence_bound,
                execution.clone(),
            ),
        };
        Verdict {
            server_keyid: parts.server_keyid.to_owned(),
            outcome,
            wire_code,
            bound,
            execution_status: execution.execution_status,
            retry_safety: execution.retry_safety,
            continuation_status: execution.continuation_status,
            retention_status: execution.retention_status,
            resp_evidence_digest_alg: parts.resp_evidence_digest_alg.to_owned(),
            resp_evidence_digest_value: parts.resp_evidence_digest_value.to_owned(),
            request_state: parts.request_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;
    use super::VerifiedParts;
    use mcp_re_client_core::DelegatedOutcome;
    use mcp_re_client_core::ExecutionContract;

    fn rejection(execution: ExecutionContract) -> DelegatedOutcome {
        DelegatedOutcome::Rejection {
            wire_code: Some("mcp-re.replay_detected".to_owned()),
            execution,
        }
    }

    fn project(outcome: &DelegatedOutcome, bound: bool, state: Option<String>) -> Verdict {
        Verdict::project(VerifiedParts {
            server_keyid: "k",
            outcome,
            evidence_bound: bound,
            resp_evidence_digest_alg: "sha256",
            resp_evidence_digest_value: "d",
            request_state: state,
        })
    }

    #[test]
    fn an_absent_execution_member_stays_absent_in_the_projection() {
        let stated = ExecutionContract {
            execution_status: Some("executed".to_owned()),
            retry_safety: None,
            continuation_status: None,
            retention_status: Some("failed".to_owned()),
        };
        let out = project(&rejection(stated), true, None);
        assert_eq!(out.execution_status.as_deref(), Some("executed"));
        assert_eq!(out.retention_status.as_deref(), Some("failed"));
        assert_eq!(out.retry_safety, None);
        assert_eq!(out.continuation_status, None);
        let silent = project(&rejection(ExecutionContract::default()), true, None);
        assert_eq!(silent.execution_status, None);
        assert_eq!(silent.retry_safety, None);
        assert_eq!(silent.continuation_status, None);
        assert_eq!(silent.retention_status, None);
    }

    #[test]
    fn a_rejection_is_not_reported_as_a_success() {
        let out = project(&rejection(ExecutionContract::default()), false, None);
        assert_eq!(out.outcome, "rejection");
        assert_eq!(out.wire_code.as_deref(), Some("mcp-re.replay_detected"));
        assert!(!out.bound, "an unbound rejection is reported unbound");
        let success = project(&DelegatedOutcome::Success, false, Some("s".to_owned()));
        assert_eq!(success.outcome, "success");
        assert_eq!(success.wire_code, None);
        assert!(success.bound);
        assert_eq!(success.request_state.as_deref(), Some("s"));
        assert_eq!(success.resp_evidence_digest_alg, "sha256");
        assert_eq!(success.resp_evidence_digest_value, "d");
        assert_eq!(success.server_keyid, "k");
    }
}
