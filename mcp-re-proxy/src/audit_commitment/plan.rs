// SPDX-License-Identifier: Apache-2.0
//! The requested audit policy resolved against what the build registered, before any
//! effect (ADR-MCPRE-070 §2, §11).

use std::sync::Arc;
use std::time::Duration;

use crate::config_state::AuditState;

use super::accounting::CommitmentAccounting;
use super::ProviderId;
use super::{
    AuditPostureRefusal, AuditProviders, CommitmentAuthority, EstablishedAudit, EstablishedProvider,
};

/// How long a provider's startup probe may take before startup is refused.
pub(crate) const ESTABLISH_BOUND: Duration = Duration::from_secs(10);

/// What the deployment's audit posture will be, decided purely from layer A's state and
/// the build's registered providers.
///
/// Resolving is the first audit decision of a run, and it has no effect: a required posture
/// with no provider, or with the reference authority unacknowledged, is refused here —
/// before trust, replay or TLS materialize — so it fails startup, not the first request.
pub(crate) enum AuditPlan {
    /// Observation only. A registered provider is NOT promoted: it is named, never asked.
    BestEffort {
        /// A provider the build registered and this posture does not use.
        unused: Option<ProviderId>,
    },
    /// Commitment is required, through `authority`, counted by `accounting`.
    Required {
        /// The registered provider, not yet established.
        authority: Arc<dyn CommitmentAuthority>,
        /// Its counters and budget, shared with the run's entry point for the shutdown
        /// report.
        accounting: Arc<CommitmentAccounting>,
    },
}

impl AuditPlan {
    /// Resolve `state` against `providers`, with a commitment budget of `ceiling`.
    ///
    /// Never a fallback: `Required` with no provider is a refusal, not best-effort, and a
    /// registered provider under best-effort stays unused (S4).
    pub(crate) fn resolve(
        state: AuditState,
        providers: &AuditProviders,
        ceiling: usize,
    ) -> Result<Self, AuditPostureRefusal> {
        let registered = providers.commitment();
        if !state.requires_commitment() {
            return Ok(AuditPlan::BestEffort {
                unused: registered.map(|authority| authority.provider_id()),
            });
        }
        let authority = registered.ok_or(AuditPostureRefusal::NoProviderInBuild)?;
        let provider = authority.provider_id();
        if provider.is_reference() && !providers.reference_acknowledged() {
            return Err(AuditPostureRefusal::ReferenceAuthority);
        }
        Ok(AuditPlan::Required {
            authority: Arc::clone(authority),
            accounting: Arc::new(CommitmentAccounting::new(provider, ceiling)),
        })
    }

    /// The commitment accounting, when commitment is required.
    pub(crate) fn accounting(&self) -> Option<Arc<CommitmentAccounting>> {
        match self {
            AuditPlan::BestEffort { .. } => None,
            AuditPlan::Required { accounting, .. } => Some(Arc::clone(accounting)),
        }
    }

    /// A best-effort plan, established: it asks nothing and needs no runtime. A required
    /// plan is handed back for [`AuditPlan::establish`].
    pub(crate) fn without_commitment(self) -> Result<EstablishedAudit, Self> {
        match self {
            AuditPlan::BestEffort { unused } => Ok(EstablishedAudit::BestEffort { unused }),
            required @ AuditPlan::Required { .. } => Err(required),
        }
    }

    /// Establish what the plan requires: nothing under best-effort, the provider under
    /// required — its tier checked and its probe answered within [`ESTABLISH_BOUND`].
    pub(crate) async fn establish(self) -> Result<EstablishedAudit, AuditPostureRefusal> {
        match self {
            AuditPlan::BestEffort { unused } => Ok(EstablishedAudit::BestEffort { unused }),
            AuditPlan::Required {
                authority,
                accounting,
            } => EstablishedProvider::establish(authority, accounting, ESTABLISH_BOUND)
                .await
                .map(EstablishedAudit::Required),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::budget::BUDGET_CEILING;
    use crate::audit_commitment::ReferenceCommitment;

    fn resolve(state: AuditState, providers: &AuditProviders) -> Result<AuditPlan, String> {
        AuditPlan::resolve(state, providers, BUDGET_CEILING).map_err(|r| r.to_string())
    }

    /// S4: required with no provider is refused — never resolved to best-effort.
    #[test]
    fn required_without_a_provider_is_refused_never_best_effort() {
        let refused = resolve(AuditState::Required, &AuditProviders::none())
            .err()
            .expect("refused");
        assert!(
            refused.contains("registers no commitment provider"),
            "{refused}"
        );
    }

    /// §9: the reference authority is refused unless it was registered as a test fixture.
    #[test]
    fn the_reference_authority_is_refused_without_the_acknowledgement() {
        let reference = ReferenceCommitment::surviving_process_loss([]);
        let unacknowledged = AuditProviders::with_commitment(reference.authority());
        let refused = resolve(AuditState::Required, &unacknowledged)
            .err()
            .expect("refused");
        assert!(
            refused.contains("test-only reference authority"),
            "{refused}"
        );
        let acknowledged = AuditProviders::with_reference_for_test(&reference);
        assert!(matches!(
            resolve(AuditState::Required, &acknowledged),
            Ok(AuditPlan::Required { .. })
        ));
    }

    /// A registered provider under best-effort is named and not promoted.
    #[test]
    fn a_registered_provider_is_not_promoted_under_best_effort() {
        let reference = ReferenceCommitment::surviving_process_loss([]);
        let providers = AuditProviders::with_reference_for_test(&reference);
        for state in [AuditState::Stderr, AuditState::None] {
            match resolve(state, &providers) {
                Ok(AuditPlan::BestEffort { unused: Some(id) }) => {
                    assert_eq!(id.as_str(), "reference")
                }
                _ => panic!("best-effort must stay best-effort"),
            }
        }
        assert_eq!(
            reference.requests(),
            0,
            "an unused provider is asked nothing"
        );
    }

    /// Establishment under best-effort establishes nothing and asks nobody.
    #[tokio::test]
    async fn best_effort_establishes_nothing() {
        let plan = resolve(AuditState::Stderr, &AuditProviders::none()).expect("resolved");
        assert!(plan.accounting().is_none());
        assert!(matches!(
            plan.establish().await,
            Ok(EstablishedAudit::BestEffort { unused: None })
        ));
    }
}
