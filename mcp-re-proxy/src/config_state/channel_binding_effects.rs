// SPDX-License-Identifier: Apache-2.0
//! What a recognised channel binding installs on the serving path.
//!
//! [`ChannelBindingState`] is the authority: `config_state::transport` decides whether a
//! deployment is channel-bound and how, and [`ChannelBindingState::serving_effects`] is the
//! only place that answer becomes an effect. It is a projection, not a seal: the state is a
//! fieldless enum whose variants the owner already publishes.
//!
//! The three effects are one decision and are produced together: the binding that compares
//! the verified request signer with the channel identity, the certificate field that
//! identity is read from, and where the connection seam reads the peer's identity. Two
//! derivations of them could disagree; one cannot.
//!
//! Every state in the model binds exactly and reads the verified peer certificate, so the
//! binding and the provenance do not vary today; what the state carries is which SAN the
//! identity comes from. The `PeerIdentityProvenance` arm this projection never yields
//! serves a capability the boundary refuses and `docs/AGENT_INSTRUCTIONS.md` item 9 retains
//! (Mode B / Mode C): a binding that is not `Exact` produces no `ChannelBindingState`, so no
//! validated deployment reaches it. If a refused mode is ever admitted it becomes a state,
//! the match below stops compiling, and its arm is wired here.

use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
use crate::config_state::ChannelBindingState;
use crate::transport::{IdentityPolicy, TransportBinding};

/// The serving-path effects of one recognised [`ChannelBindingState`].
pub(crate) struct ChannelBindingEffects {
    /// Compares the verified request signer with the channel identity.
    pub(crate) binding: TransportBinding,
    /// The certificate field the channel identity is read from.
    pub(crate) identity_policy: IdentityPolicy,
    /// Where the connection seam reads the peer's identity from.
    pub(crate) peer_identity_provenance: PeerIdentityProvenance,
}

impl ChannelBindingState {
    /// Project this state onto the serving path.
    pub(crate) fn serving_effects(self) -> ChannelBindingEffects {
        let identity_policy = match self {
            ChannelBindingState::ExactUriSan => IdentityPolicy::UriSan,
            ChannelBindingState::ExactDnsSan => IdentityPolicy::DnsSan,
        };
        ChannelBindingEffects {
            binding: TransportBinding::exact_match(),
            identity_policy,
            peer_identity_provenance: PeerIdentityProvenance::ChannelCredential,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChannelBindingState;
    use super::PeerIdentityProvenance;
    use crate::transport::IdentityPolicy;

    /// Each state reads its own SAN, and every state reads the identity from the verified
    /// peer certificate.
    #[test]
    fn each_state_projects_its_own_san_and_the_channel_credential() {
        for (state, policy) in [
            (ChannelBindingState::ExactUriSan, IdentityPolicy::UriSan),
            (ChannelBindingState::ExactDnsSan, IdentityPolicy::DnsSan),
        ] {
            let effects = state.serving_effects();
            assert_eq!(effects.identity_policy, policy, "{state:?}");
            assert!(
                matches!(
                    effects.peer_identity_provenance,
                    PeerIdentityProvenance::ChannelCredential
                ),
                "{state:?} must read the identity from the verified peer certificate"
            );
        }
    }
}
