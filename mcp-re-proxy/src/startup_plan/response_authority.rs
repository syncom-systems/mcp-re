// SPDX-License-Identifier: Apache-2.0
//! The response authority: the root issuer kid delegated credentials chain to, and the trust
//! epoch they are minted under, decided once for both planes that act on them.

use super::{SigningPlan, TrustEpochPlan, TrustPlan};
use crate::config_state::validation::ValidatedDeployment;

/// The root issuer kid (ADR-MCPRE-052) and the shared trust epoch (CF-09), as one value.
///
/// Two planes consume both facts: trust excludes the kid from the request-signer set and
/// flushes its cache when the epoch advances, and delegated signing mints under the kid and
/// the epoch's label. Each fact is read here once, from what layer A decided — the kid from
/// [`DelegatedSigningFacts`](crate::config_state::DelegatedSigningFacts), the epoch from the
/// classified trust-revocation state — so trust never enrolls as a request signer a kid
/// other than the one signing mints under, and the two follow one epoch.
///
/// The fields are private to this module and `from_validated` is private too, called only
/// by [`response_authority_plans`]. Both plan constructors take the authority whole, so
/// neither plan can be built around a kid or an epoch that this module did not read, and
/// neither plan can re-derive one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseAuthority {
    /// The root issuer delegated credentials chain to.
    kid: String,
    /// The shared epoch mechanism.
    epoch: TrustEpochPlan,
}

impl ResponseAuthority {
    /// Read both facts from one validated deployment.
    ///
    /// Infallible: the issuer kid's fallback to the server key id is the delegated-signing
    /// owner's, and the epoch source is the trust-revocation classification's.
    fn from_validated(config: &ValidatedDeployment) -> ResponseAuthority {
        ResponseAuthority {
            kid: config.state().delegated_signing().issuer_kid().to_string(),
            epoch: TrustEpochPlan::from_validated(config),
        }
    }

    /// The root issuer delegated credentials chain to.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The shared epoch mechanism.
    pub fn epoch(&self) -> &TrustEpochPlan {
        &self.epoch
    }
}

/// The trust plan and the signing plan, produced together around one response authority.
///
/// The only producer of a [`ResponseAuthority`], and so of both plans in production.
pub fn response_authority_plans(config: &ValidatedDeployment) -> (TrustPlan, SigningPlan) {
    let authority = ResponseAuthority::from_validated(config);
    (
        TrustPlan::from_validated(config, authority.clone()),
        SigningPlan::from_validated(config, authority),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validated() -> ValidatedDeployment {
        ValidatedDeployment::try_from(crate::config_state::test_support::legal_config())
            .expect("the fixture is a legal deployment")
    }

    /// An authority naming a kid and an epoch the configuration does not name. Only this
    /// module can build one, which is why the two tests below live here.
    fn decided_above() -> ResponseAuthority {
        ResponseAuthority {
            kid: "decided-above".to_string(),
            epoch: TrustEpochPlan::redis("redis://198.51.100.1:6379", "decided-above"),
        }
    }

    /// The authority reads the kid and the epoch from the owners that decided them.
    #[test]
    fn the_authority_reads_what_layer_a_decided() {
        let config = validated();
        let authority = ResponseAuthority::from_validated(&config);
        assert_eq!(
            authority.kid(),
            config.state().delegated_signing().issuer_kid()
        );
        assert_eq!(*authority.epoch(), TrustEpochPlan::from_validated(&config));
    }

    /// The trust plan carries the authority it is handed: a plan built around a kid and an
    /// epoch the configuration does not name carries them, which is only possible because
    /// nothing inside the trust plan re-derives either (CF-09).
    #[test]
    fn the_trust_plan_carries_the_authority_it_is_handed() {
        let config = validated();
        assert_ne!(
            ResponseAuthority::from_validated(&config),
            decided_above(),
            "the fixture must not coincide with what a re-derivation would produce"
        );
        let plan = TrustPlan::from_validated(&config, decided_above());
        assert_eq!(plan.response_kid(), "decided-above");
        assert_eq!(*plan.epoch(), *decided_above().epoch());
    }

    /// The issuer kid in the credential is the one the authority carries.
    ///
    /// The defect this closes: the kid was derived twice — by the planner, whose value the
    /// startup transcript prints and which trust excludes from the request-signer set, and
    /// again inside the delegated wiring, which is the one that reached the credential. Both
    /// spelled the same fallback, so they agreed. A deployment could otherwise have been told
    /// it was chaining to one issuer while minting under another.
    #[test]
    fn the_issuer_kid_in_the_credential_is_the_one_that_was_planned() {
        let plan = SigningPlan::from_validated(&validated(), decided_above());
        assert_eq!(
            plan.custody().issuer_kid,
            "decided-above",
            "the credential must be minted under the planned issuer, not a re-derived one"
        );
        assert_eq!(*plan.epoch(), *decided_above().epoch());
    }
}
