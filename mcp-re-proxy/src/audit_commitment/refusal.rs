// SPDX-License-Identifier: Apache-2.0
//! Why the required audit posture refuses startup (ADR-MCPRE-070 §2 S4, §11, D3).

use std::time::Duration;

use super::{DurabilityTier, EstablishFailure, ProviderId};

/// A required posture that cannot be established. Every arm is a startup refusal: the
/// required posture is never downgraded to best-effort, never served over `--audit-sink
/// none` (layer A refuses that combination), and never declared OFF (S4).
///
/// The rendering prints only the provider's [`ProviderId`], a tier's wire name, a failure
/// class and a bound — never text a provider produced, so a provider's settings or secrets
/// cannot reach a diagnostic through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditPostureRefusal {
    /// The build registers no commitment provider (the open-source binary registers none).
    NoProviderInBuild,
    /// The registered provider is the test-only reference authority, registered without the
    /// test acknowledgement (§9).
    ReferenceAuthority,
    /// The provider declared a tier below the minimum (D3).
    TierBelowMinimum {
        /// The provider.
        provider: ProviderId,
        /// What it declared.
        declared: DurabilityTier,
    },
    /// The provider's establishment failed, or panicked (reported as `Refused`).
    EstablishFailed {
        /// The provider.
        provider: ProviderId,
        /// The class it answered with.
        class: EstablishFailure,
    },
    /// The provider's establishment did not answer within the bound.
    EstablishTimedOut {
        /// The provider.
        provider: ProviderId,
        /// The bound.
        bound: Duration,
    },
}

impl std::fmt::Display for AuditPostureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("--audit-commitment required: ")?;
        match self {
            AuditPostureRefusal::NoProviderInBuild => f.write_str(
                "this binary registers no commitment provider (the open-source build has \
                 none); a required posture is never downgraded to best-effort. Use a build \
                 that registers a qualified provider, or pass --audit-commitment best-effort",
            ),
            AuditPostureRefusal::ReferenceAuthority => f.write_str(
                "the registered provider is the test-only reference authority, which is never \
                 a deployment's backend (ADR-MCPRE-070 §9)",
            ),
            AuditPostureRefusal::TierBelowMinimum { provider, declared } => write!(
                f,
                "provider {provider} declares tier {} ({}), below the minimum \
                 SURVIVES_PROXY_PROCESS_LOSS (ADR-MCPRE-070 D3)",
                declared.wire_name(),
                super::tier::TIER_VOCABULARY
            ),
            AuditPostureRefusal::EstablishFailed { provider, class } => write!(
                f,
                "provider {provider} could not be established: {}",
                class.wire_name()
            ),
            AuditPostureRefusal::EstablishTimedOut { provider, bound } => write!(
                f,
                "provider {provider} was not established within {}ms",
                bound.as_millis()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> ProviderId {
        ProviderId::new("journal").expect("legal")
    }

    /// Every refusal names the flag and says the posture was not downgraded or served.
    #[test]
    fn every_refusal_names_the_flag() {
        for refusal in [
            AuditPostureRefusal::NoProviderInBuild,
            AuditPostureRefusal::ReferenceAuthority,
            AuditPostureRefusal::TierBelowMinimum {
                provider: journal(),
                declared: DurabilityTier::ProcessVolatile,
            },
            AuditPostureRefusal::EstablishFailed {
                provider: journal(),
                class: EstablishFailure::Unauthorized,
            },
            AuditPostureRefusal::EstablishTimedOut {
                provider: journal(),
                bound: Duration::from_millis(50),
            },
        ] {
            let rendered = refusal.to_string();
            assert!(
                rendered.starts_with("--audit-commitment required: "),
                "{rendered}"
            );
        }
        assert!(AuditPostureRefusal::NoProviderInBuild
            .to_string()
            .contains("never downgraded"));
    }

    #[test]
    fn a_tier_refusal_names_the_vocabulary_and_the_declared_tier() {
        let rendered = AuditPostureRefusal::TierBelowMinimum {
            provider: journal(),
            declared: DurabilityTier::ProcessVolatile,
        }
        .to_string();
        assert!(rendered.contains("PROCESS_VOLATILE"), "{rendered}");
        assert!(rendered.contains("audit-durability/v1"), "{rendered}");
        assert!(rendered.contains("provider journal"), "{rendered}");
    }
}
