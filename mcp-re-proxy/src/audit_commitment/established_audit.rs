// SPDX-License-Identifier: Apache-2.0
//! The commitment half of the audit posture, once established.

use std::sync::Arc;

use super::{EstablishedProvider, ProviderId};

/// What [`super::AuditPlan::establish`] established: nothing to commit to, or a provider
/// that met the minimum tier and answered its probe. There is no third state — a required
/// plan that could not be established is a refusal, never a value (S4).
#[derive(Debug)]
pub(crate) enum EstablishedAudit {
    /// Observation only; a registered provider, if any, is named and unused.
    BestEffort {
        /// A provider the build registered and this posture does not use.
        unused: Option<ProviderId>,
    },
    /// Commitment is required, through this provider.
    Required(Arc<EstablishedProvider>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The best-effort form carries no provider to commit to, only a name.
    #[test]
    fn best_effort_names_without_holding() {
        let unused = ProviderId::new("journal");
        let established = EstablishedAudit::BestEffort {
            unused: unused.clone(),
        };
        assert!(matches!(established, EstablishedAudit::BestEffort { unused: u } if u == unused));
    }
}
