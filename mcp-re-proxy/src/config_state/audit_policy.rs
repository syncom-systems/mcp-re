// SPDX-License-Identifier: Apache-2.0
//! The `Audit` machine — where the per-request security record is observed, and whether
//! its commitment is required (ADR-MCPS-035, ADR-MCPRE-070 §2).
//!
//! A REFUSABLE machine. Of the four request forms, three are legal deployments and one is
//! not: a required delivery over `--audit-sink none` would commit facts no operator line
//! names, so the request is refused here rather than either half being silently changed
//! (ADR-MCPRE-070 §11, S4). The rule is between two selectors of this one machine, which is
//! why it is the machine's own column and not a cross-machine relation.

use crate::deployment_request::{AuditDeliveryKind, AuditSinkKind, DeploymentRequest};

/// The refusal for a required delivery with no observer.
pub(crate) const REQUIRED_WITHOUT_OBSERVER: &str =
    "--audit-commitment required needs the stderr observer: with --audit-sink none the \
     required posture would commit facts no operator line names (ADR-MCPRE-070 §5, §11); \
     pass --audit-sink stderr, or --audit-commitment best-effort";

/// Where records are observed, and how they are delivered. The illegal fourth form —
/// required delivery with no observer — is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// No per-request record is written, and nothing is committed.
    None,
    /// One structured record per decision on stderr, best-effort: it never affects a request.
    Stderr,
    /// Records observed on stderr, and an execution intent and an outcome committed through
    /// the build's commitment provider before dispatch and before visible success.
    Required,
}

impl AuditState {
    /// Whether records are observed on stderr.
    pub fn observes_on_stderr(&self) -> bool {
        !matches!(self, AuditState::None)
    }

    /// Whether commitment is a prerequisite of dispatch and of visible success.
    pub fn requires_commitment(&self) -> bool {
        matches!(self, AuditState::Required)
    }
}

/// Classify the audit request, or refuse it.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<AuditState>, Vec<String>) {
    match (config.audit.sink, config.audit.delivery) {
        (AuditSinkKind::None, AuditDeliveryKind::BestEffort) => (Some(AuditState::None), vec![]),
        (AuditSinkKind::Stderr, AuditDeliveryKind::BestEffort) => {
            (Some(AuditState::Stderr), vec![])
        }
        (AuditSinkKind::Stderr, AuditDeliveryKind::Required) => {
            (Some(AuditState::Required), vec![])
        }
        (AuditSinkKind::None, AuditDeliveryKind::Required) => {
            (None, vec![REQUIRED_WITHOUT_OBSERVER.to_string()])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::AuditRequest;

    fn classify(
        sink: AuditSinkKind,
        delivery: AuditDeliveryKind,
    ) -> (Option<AuditState>, Vec<String>) {
        let mut config = legal_config();
        config.audit = AuditRequest { sink, delivery };
        classify_and_validate(&config)
    }

    #[test]
    fn the_three_legal_forms_are_classified() {
        use AuditDeliveryKind::{BestEffort, Required};
        assert_eq!(
            classify(AuditSinkKind::None, BestEffort),
            (Some(AuditState::None), vec![])
        );
        assert_eq!(
            classify(AuditSinkKind::Stderr, BestEffort),
            (Some(AuditState::Stderr), vec![])
        );
        assert_eq!(
            classify(AuditSinkKind::Stderr, Required),
            (Some(AuditState::Required), vec![])
        );
    }

    /// S4: a required delivery over no observer is refused, never downgraded to best-effort
    /// and never served with the observer silently switched on.
    #[test]
    fn required_without_an_observer_is_refused_not_downgraded() {
        let (state, refusals) = classify(AuditSinkKind::None, AuditDeliveryKind::Required);
        assert_eq!(state, None);
        assert_eq!(refusals, vec![REQUIRED_WITHOUT_OBSERVER.to_string()]);
        assert!(REQUIRED_WITHOUT_OBSERVER.contains("--audit-sink none"));
    }

    #[test]
    fn the_projections_follow_the_state() {
        assert!(!AuditState::None.observes_on_stderr());
        assert!(
            AuditState::Stderr.observes_on_stderr() && !AuditState::Stderr.requires_commitment()
        );
        assert!(
            AuditState::Required.observes_on_stderr() && AuditState::Required.requires_commitment()
        );
    }
}
