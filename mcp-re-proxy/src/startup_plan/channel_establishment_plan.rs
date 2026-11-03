// SPDX-License-Identifier: Apache-2.0
//! The channel-establishment plan: what this node needs to establish authenticated channels,
//! projected once from a validated deployment.

use crate::config_state::crl_revocation::ClientRevocationPlan;
use crate::config_state::validation::ValidatedDeployment;
use crate::config_state::{
    credential_currency_bound, ClientCredentialWindow, CredentialCurrencyBound,
};
use crate::delegated_tls::HandshakeSignCapacity;

/// What must hold for this node to establish authenticated channels (ADR-MCPRE-056 §8).
///
/// Three classified states, none of them protocol vocabulary: the custody of this node's
/// own channel credential, the currency posture it holds peer credentials to, and the
/// window a peer credential authorizes traffic for. The mechanism that consumes them is
/// `TlsPlane`, and it is the plane — not the plan — that is entitled to say rustls
/// (ADR-MCPRE-067 §5, §6). The certificate lifetime and the connection-age bound used to
/// travel here as two `Option<Duration>` inputs, with a doc comment claiming their
/// compatibility "was settled at layer A" — which was not true: relation X5 compared the
/// connection age against the ceiling CONSTANT and never against the configured lifetime.
/// `ClientCredentialWindow` states the relation over the chosen values and owns both, so
/// the plan carries one fact instead of two durations that could disagree.
///
/// The fields are private to this module and `from_validated` is the only producer, so
/// holding a plan means all three facts came from ONE validated deployment. Consumers get
/// projections, and the revocation posture and the credential window, which bound peer
/// currency only together, are projected as that bound rather than as two terms a caller
/// could re-pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEstablishmentPlan {
    /// The offline peer-credential revocation posture.
    client_revocation: ClientRevocationPlan,
    /// How long a client credential authorizes traffic, and how long one connection may
    /// serve on a single handshake — the pair that makes the exposure window honest.
    credential_window: ClientCredentialWindow,
    /// The capacity of the listener's handshake-signature budget: a global ceiling on the
    /// signing backend, not a per-peer allowance.
    handshake_signing: HandshakeSignCapacity,
}

impl ChannelEstablishmentPlan {
    /// Project the plan from the retained classification and the validated inputs.
    ///
    /// **Infallible, deliberately.** Whether this binary has a PKCS#11, AWS or GCP backend
    /// for delegated custody is a fact about the BUILD, and making this fallible for it
    /// would collapse the A/B split: the request is coherent either way, and only
    /// materialization can say whether this executable can serve it.
    pub fn from_validated(config: &ValidatedDeployment) -> ChannelEstablishmentPlan {
        ChannelEstablishmentPlan {
            client_revocation: config.state().crl_revocation().client_revocation_plan(),
            credential_window: config.state().client_credential_window(),
            handshake_signing: config.config().limits.tls_handshake_signing,
        }
    }

    /// The CRL files this node loads at startup and re-reads on every reload; empty when
    /// the deployment configured none.
    pub fn crl_paths(&self) -> &[String] {
        self.client_revocation.paths()
    }

    /// The reload cadence the revocation posture schedules, or `None` when nothing
    /// re-reads the CRLs.
    pub fn crl_reload_cadence_secs(&self) -> Option<u64> {
        self.client_revocation.reload_cadence_secs()
    }

    /// What bounds a peer credential's currency under this plan: the revocation posture
    /// and the credential window, related here rather than by a caller holding both.
    pub fn currency_bound(&self) -> CredentialCurrencyBound {
        credential_currency_bound(&self.client_revocation, &self.credential_window)
    }

    /// The validated credential window: the lifetime, the connection age and the
    /// exposure window they make honest.
    pub fn credential_window(&self) -> ClientCredentialWindow {
        self.credential_window
    }

    /// The capacity the listener's handshake-signature budget is built with.
    pub fn handshake_capacity(&self) -> HandshakeSignCapacity {
        self.handshake_signing
    }
}

/// The channel-establishment plan a deployment with these CRLs, this credential window
/// and this handshake-signing capacity projects.
///
/// Through the validation boundary and `ChannelEstablishmentPlan::from_validated`, the
/// plan's only producer, so a fixture holds three facts one accepted deployment could
/// hold together and nothing a literal could pair instead.
#[cfg(test)]
pub(crate) fn channel_plan(
    crl_paths: &[&str],
    cadence_secs: Option<u64>,
    cert_lifetime_secs: u64,
    connection_age_secs: u64,
    handshake_signing: HandshakeSignCapacity,
) -> ChannelEstablishmentPlan {
    let mut config = crate::config_state::test_support::legal_config();
    config.peer_revocation.lists.paths = crl_paths.iter().map(|p| p.to_string()).collect();
    config.peer_revocation.lists.reload_secs = cadence_secs;
    config.max_client_cert_lifetime = Some(std::time::Duration::from_secs(cert_lifetime_secs));
    config.limits.max_connection_age = Some(std::time::Duration::from_secs(connection_age_secs));
    config.limits.tls_handshake_signing = handshake_signing;
    let validated =
        ValidatedDeployment::try_from(config).expect("the fixture names a legal channel posture");
    ChannelEstablishmentPlan::from_validated(&validated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound is the plan's own posture and window related: with no CRL the window
    /// bounds currency, and with a scheduled reload the cadence does.
    #[test]
    fn the_currency_bound_relates_the_plans_own_posture_and_window() {
        let default = HandshakeSignCapacity::default();
        assert_eq!(
            channel_plan(&[], None, 3600, 300, default).currency_bound(),
            CredentialCurrencyBound::CredentialLifetime { window_secs: 3600 }
        );
        assert_eq!(
            channel_plan(&["/crl.pem"], Some(60), 3600, 300, default).currency_bound(),
            CredentialCurrencyBound::PublicationRefresh { cadence_secs: 60 }
        );
        assert_eq!(
            channel_plan(&["/crl.pem"], None, 3600, 300, default).currency_bound(),
            CredentialCurrencyBound::PublicationValidity
        );
    }

    /// Each projection answers with what the validated deployment stated.
    #[test]
    fn each_projection_answers_with_what_the_deployment_stated() {
        let capacity = HandshakeSignCapacity::new(250, 40).expect("in bounds");
        let plan = channel_plan(&["/a.pem", "/b.pem"], Some(300), 1800, 120, capacity);
        assert_eq!(
            plan.crl_paths(),
            ["/a.pem".to_string(), "/b.pem".to_string()]
        );
        assert_eq!(plan.crl_reload_cadence_secs(), Some(300));
        assert_eq!(
            plan.credential_window().cert_lifetime(),
            std::time::Duration::from_secs(1800)
        );
        assert_eq!(
            plan.credential_window().connection_age(),
            std::time::Duration::from_secs(120)
        );
        assert_eq!(plan.handshake_capacity(), capacity);
    }
}
