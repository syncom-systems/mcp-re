// SPDX-License-Identifier: Apache-2.0
//! What a build registers for the audit posture to use: the injection seam (#1206).

use std::sync::Arc;

use super::CommitmentAuthority;

/// The commitment providers a build registers — at most one.
///
/// The open-source binary passes [`AuditProviders::none`], so it can never establish the
/// required posture: `--audit-commitment required` is refused at startup there, before any
/// plane materializes (ADR-MCPRE-070 §11). A downstream build that compiles a qualified
/// provider registers it with [`AuditProviders::with_commitment`] and hands this value to
/// `app::run_with`.
///
/// Registering a provider selects nothing. Whether it is used is the operator's
/// `--audit-commitment` choice: under best-effort a registered provider is reported as
/// present and NOT used, and is never asked anything.
///
/// It carries no replay handle and no runtime: audit and replay resources are configured
/// independently, and no replay connection pool is shared with a provider (§12).
#[derive(Clone, Default)]
pub struct AuditProviders {
    commitment: Option<Arc<dyn CommitmentAuthority>>,
    /// The reference authority was registered through the test acknowledgement.
    reference_acknowledged: bool,
}

impl AuditProviders {
    /// No provider: what the open-source binary registers.
    pub fn none() -> Self {
        AuditProviders::default()
    }

    /// `authority` as the commitment provider.
    pub fn with_commitment(authority: Arc<dyn CommitmentAuthority>) -> Self {
        AuditProviders {
            commitment: Some(authority),
            reference_acknowledged: false,
        }
    }

    /// The test-only reference authority, registered with the acknowledgement that it is a
    /// test fixture and never a backend (§9). Test builds and the test-only
    /// `audit_commitment_reference` flavor only: no deployable library compiles it.
    #[cfg(any(test, feature = "audit_commitment_reference"))]
    pub fn with_reference_for_test(reference: &super::ReferenceCommitment) -> Self {
        AuditProviders {
            commitment: Some(reference.authority()),
            reference_acknowledged: true,
        }
    }

    /// The registered provider, if any.
    pub(super) fn commitment(&self) -> Option<&Arc<dyn CommitmentAuthority>> {
        self.commitment.as_ref()
    }

    /// Whether a reference authority, if registered, was registered as a test fixture.
    pub(super) fn reference_acknowledged(&self) -> bool {
        self.reference_acknowledged
    }
}

impl std::fmt::Debug for AuditProviders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditProviders")
            .field(
                "commitment",
                &self.commitment.as_ref().map(|a| a.provider_id()),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::ReferenceCommitment;

    #[test]
    fn none_registers_nothing() {
        assert!(AuditProviders::none().commitment().is_none());
    }

    /// Only the test constructor acknowledges the reference authority.
    #[test]
    fn only_the_test_constructor_acknowledges_the_reference() {
        let reference = ReferenceCommitment::surviving_process_loss([]);
        assert!(AuditProviders::with_reference_for_test(&reference).reference_acknowledged());
        assert!(!AuditProviders::with_commitment(reference.authority()).reference_acknowledged());
    }
}
