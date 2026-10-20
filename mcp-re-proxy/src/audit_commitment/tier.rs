// SPDX-License-Identifier: Apache-2.0
//! The declared durability tier of a commitment authority (ADR-MCPRE-070 §2, D3).

/// The version of the tier vocabulary below. A tier is added only together with a new
/// version, because a closed vocabulary that grows in place makes an old reading of a wire
/// name silently mean something else.
#[cfg_attr(not(test), allow(dead_code))] // published by the posture line; no emitter reads it yet
pub(crate) const TIER_VOCABULARY: &str = "audit-durability/v1";

/// What a commitment authority DECLARES its acknowledged writes survive.
///
/// A **declaration**, never a property this crate proves (D3). The shared owner binds a
/// witness to the tier the provider declared when it was established and refuses a receipt
/// that claims another; whether the provider's storage actually survives the fault it names
/// is an assumption with its own, external evidence (ADR-MCPRE-070 P9).
///
/// The vocabulary is CLOSED and carries no ordering: there is no `PartialOrd`, and the one
/// policy threshold is [`DurabilityTier::meets_required_minimum`]. A tier stronger than the
/// minimum (surviving loss of a provider node, say) arrives with a vocabulary version and
/// the first provider that declares it, never ahead of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // declared by providers; none is compiled outside tests
pub(crate) enum DurabilityTier {
    /// Lost with the proxy process. Never eligible for the required posture.
    ProcessVolatile,
    /// Survives crash-stop of the proxy process (SIGKILL, OOM), under the provider's
    /// declared fault model. The minimum eligible tier (D3).
    SurvivesProxyProcessLoss,
}

impl DurabilityTier {
    /// The published spelling of this tier within [`TIER_VOCABULARY`].
    #[cfg_attr(not(test), allow(dead_code))] // published by the posture line; no emitter reads it yet
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            DurabilityTier::ProcessVolatile => "PROCESS_VOLATILE",
            DurabilityTier::SurvivesProxyProcessLoss => "SURVIVES_PROXY_PROCESS_LOSS",
        }
    }

    /// The honest guarantee this tier supports. Conditional by construction: no tier's
    /// guarantee holds independently of the provider's declaration.
    #[cfg_attr(not(test), allow(dead_code))] // published by the posture line; no emitter reads it yet
    pub(crate) fn guarantee(self) -> &'static str {
        match self {
            DurabilityTier::ProcessVolatile => {
                "none: an acknowledged event is lost with the proxy process"
            }
            DurabilityTier::SurvivesProxyProcessLoss => {
                "an acknowledged event survives crash-stop of the proxy process, conditional \
                 on the provider's declared fault model; not across provider loss"
            }
        }
    }

    /// Whether a provider at this tier may serve the required posture (D3). The ONLY
    /// ordering this type asserts, and it is a policy threshold, not "stronger than".
    pub(crate) fn meets_required_minimum(self) -> bool {
        matches!(self, DurabilityTier::SurvivesProxyProcessLoss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tier, through an exhaustive match: adding a variant without deciding it here
    /// does not compile.
    fn all() -> [DurabilityTier; 2] {
        let decided = |t: DurabilityTier| match t {
            DurabilityTier::ProcessVolatile | DurabilityTier::SurvivesProxyProcessLoss => t,
        };
        [
            decided(DurabilityTier::ProcessVolatile),
            decided(DurabilityTier::SurvivesProxyProcessLoss),
        ]
    }

    #[test]
    fn the_vocabulary_is_closed_at_two_in_v1() {
        assert_eq!(TIER_VOCABULARY, "audit-durability/v1");
        assert_eq!(
            all().map(DurabilityTier::wire_name),
            ["PROCESS_VOLATILE", "SURVIVES_PROXY_PROCESS_LOSS"]
        );
    }

    #[test]
    fn only_survives_proxy_process_loss_meets_the_required_minimum() {
        let eligible: Vec<_> = all()
            .into_iter()
            .filter(|t| t.meets_required_minimum())
            .collect();
        assert_eq!(eligible, [DurabilityTier::SurvivesProxyProcessLoss]);
    }

    #[test]
    fn no_guarantee_claims_unconditional_durability() {
        for tier in all() {
            let guarantee = tier.guarantee();
            assert!(!guarantee.contains("unconditional"), "{guarantee}");
            assert!(!guarantee.contains("permanent"), "{guarantee}");
        }
        assert!(DurabilityTier::SurvivesProxyProcessLoss
            .guarantee()
            .contains("conditional on the provider's declared fault model"));
    }
}
