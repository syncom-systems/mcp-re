// SPDX-License-Identifier: Apache-2.0
//! The signing plan: what response-signing custody must establish.

use super::{ResponseAuthority, TrustEpochPlan};
use crate::config_state::validation::ValidatedDeployment;

/// What response-signing custody must establish (ADR-MCPRE-052).
///
/// Delegated signing is the only response mode, so this is a STRUCT and not an enum: the
/// layer A classifies it as guard-only, with one state. The plan holds the normalized
/// custody policy, every default applied once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPlan {
    /// The credential policy the rotor mints under, fully resolved.
    custody: mcp_re_http_profile::CustodyConfig,
    /// The shared epoch mechanism, the decision the trust plan holds (CF-09).
    epoch: TrustEpochPlan,
}

impl SigningPlan {
    /// Project the plan from the validated configuration and the response authority.
    ///
    /// Infallible: the epoch source and `0 < overlap < ttl` are layer A's clauses. Visible
    /// to the startup plan only; [`response_authority_plans`](super::response_authority_plans)
    /// is the one caller.
    pub(super) fn from_validated(
        config: &ValidatedDeployment,
        authority: ResponseAuthority,
    ) -> SigningPlan {
        let values = config.config();
        let facts = config.state().delegated_signing();
        let rotation = facts.rotation_window();
        let identity = config.state().server_identity().actor();
        SigningPlan {
            custody: mcp_re_http_profile::CustodyConfig {
                issuer_kid: authority.kid().to_string(),
                iss: identity.subject.clone(),
                profile: mcp_re_http_profile::PROFILE_TAG.to_string(),
                aud: values.audience.clone(),
                audience_hash: facts.audience_hash().to_string(),
                trust_epoch: facts.trust_epoch().clone(),
                // The three identity components come from the ONE derived identity.
                server_role: identity.role.clone(),
                server_trust_domain: identity.trust_domain.clone(),
                server_subject: identity.subject.clone(),
                // The owner's sealed TTL/overlap pair, projected whole.
                window: rotation,
            },
            epoch: authority.epoch().clone(),
        }
    }

    /// The credential policy the rotor mints under.
    pub fn custody(&self) -> &mcp_re_http_profile::CustodyConfig {
        &self.custody
    }

    /// The shared epoch mechanism, the same decision the trust plan holds.
    pub fn epoch(&self) -> &TrustEpochPlan {
        &self.epoch
    }

    /// This plan minting under `epoch`, the label the signing plane read from this
    /// plan's own epoch source at startup; nothing else changes. `pub(crate)` for that one
    /// consumer, a sibling subtree.
    pub(crate) fn minting_under(&self, epoch: mcp_re_http_profile::custody::TrustEpoch) -> Self {
        let mut minting = self.clone();
        minting.custody.trust_epoch = epoch;
        minting
    }

    /// A plan from parts, for in-crate tests of the signing plane's rotation loop, which
    /// need windows and epoch sources no validated deployment states.
    #[cfg(test)]
    pub(crate) fn from_parts(
        custody: mcp_re_http_profile::CustodyConfig,
        epoch: TrustEpochPlan,
    ) -> SigningPlan {
        SigningPlan { custody, epoch }
    }
}
