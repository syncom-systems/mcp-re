// SPDX-License-Identifier: Apache-2.0
//! The machines that can REFUSE, and what they refused.
//!
//! Each answers with the state it recognised, or with `None` and the refusal that explains
//! it — so a `None` here is never an absence, it is a decision already made and already
//! reported.
//!
//! Kept apart from [`super::total_machines`] because the two are different in kind, not
//! just in length: a total machine has nothing to say because its illegal combinations are
//! not representable, and putting the two in one list invites an owner to be moved between
//! them without anyone noticing the claim changed.

use crate::config_state::cross_machine::CrossMachineViolations;
use crate::deployment_request::DeploymentRequest;

use super::machine_violations::MachineViolations;

/// Every machine's own refusals, before the cross-machine pass has run.
///
/// Separate from [`MachineViolations`] because the cross field cannot be filled yet: the
/// relation is asked of the states this pass produces.
pub(super) struct Refusals {
    admission: Vec<String>,
    audit: Vec<String>,
    authorization: Vec<String>,
    channel_binding: Vec<String>,
    continuation_control: Vec<String>,
    crl_revocation: Vec<String>,
    custody: Vec<String>,
    delegated_signing: Vec<String>,
    freshness: Vec<String>,
    connection_bounds: Vec<String>,
    mcp_transport_contract: Vec<String>,
    replay: Vec<String>,
    request_target: Vec<String>,
    trust_document: Vec<String>,
    client_credential_window: Vec<String>,
    server_identity: Vec<String>,
    channel_credential_custody: Vec<String>,
    trust_revocation: Vec<String>,
}

impl Refusals {
    /// Join the cross-machine pass's result, giving the clause list everything it splices.
    pub(super) fn with_cross(self, cross: CrossMachineViolations) -> MachineViolations {
        MachineViolations {
            admission: self.admission,
            audit: self.audit,
            authorization: self.authorization,
            channel_binding: self.channel_binding,
            continuation_control: self.continuation_control,
            crl_revocation: self.crl_revocation,
            custody: self.custody,
            delegated_signing: self.delegated_signing,
            freshness: self.freshness,
            connection_bounds: self.connection_bounds,
            mcp_transport_contract: self.mcp_transport_contract,
            replay: self.replay,
            request_target: self.request_target,
            trust_document: self.trust_document,
            client_credential_window: self.client_credential_window,
            server_identity: self.server_identity,
            channel_credential_custody: self.channel_credential_custody,
            trust_revocation: self.trust_revocation,
            cross,
        }
    }
}

/// What the machines that CAN refuse recognised.
///
/// `None` is a refusal already made, never an absence.
pub(super) struct RefusableStates {
    pub(super) admission: Option<crate::config_state::AdmissionState>,
    pub(super) audit: Option<crate::config_state::AuditState>,
    pub(super) authorization: Option<crate::config_state::AuthorizationState>,
    pub(super) channel_binding: Option<crate::config_state::ChannelBindingState>,
    pub(super) client_credential_window: Option<crate::config_state::ClientCredentialWindow>,
    pub(super) freshness: Option<crate::config_state::FreshnessWindow>,
    pub(super) connection_bounds: Option<crate::config_state::ConnectionBounds>,
    pub(super) continuation_control: Option<crate::config_state::ContinuationControlState>,
    pub(super) crl_revocation: Option<crate::config_state::CrlRevocationState>,
    pub(super) custody: Option<crate::config_state::CustodyState>,
    pub(super) delegated_signing: Option<crate::config_state::DelegatedSigningFacts>,
    pub(super) mcp_transport_contract: Option<crate::config_state::McpTransportContractState>,
    pub(super) replay: Option<crate::config_state::ReplayState>,
    pub(super) request_target: Option<crate::config_state::RequestTarget>,
    pub(super) server_identity: Option<crate::config_state::server_identity::ServerIdentityFacts>,
    pub(super) channel_credential_custody:
        Option<crate::config_state::ChannelCredentialCustodyState>,
    pub(super) trust_document: Option<crate::config_state::TrustDocumentSource>,
    pub(super) trust_revocation: Option<crate::config_state::TrustRevocationState>,
}

/// The machines that can REFUSE: each answers with the state it recognised, or with
/// `None` and the refusal that explains it.
pub(super) fn classify_refusable(config: &DeploymentRequest) -> (RefusableStates, Refusals) {
    use crate::config_state as m;
    // Each machine's answer is one value, `(state, refusals)`. The macro names a machine once
    // and splits every answer the same way, so no machine can reach one half without the other.
    macro_rules! split_answers {
        ($($machine:ident = $answer:expr),* $(,)?) => {{
            $(let $machine = $answer;)*
            (
                RefusableStates { $($machine: $machine.0,)* },
                Refusals { $($machine: $machine.1,)* },
            )
        }};
    }
    let delegated_signing = m::delegated_signing::classify_and_validate(config);
    // This deployment's own actor identity. It takes the RESOLVED issuer kid rather than
    // re-reading the primitives it defaults from, so the keyid on the identity and the kid
    // the credential chains to are one value (CF-10).
    let server_identity =
        m::server_identity::classify_and_validate(config, delegated_signing.0.as_ref());
    split_answers! {
        continuation_control = m::continuation_control::classify_and_validate(config),
        custody = m::custody::classify_and_validate(config),
        delegated_signing = delegated_signing,
        replay = m::replay::classify_and_validate(config),
        channel_credential_custody = m::channel_credential_custody::classify_and_validate(config),
        trust_revocation = m::trust_revocation::classify_and_validate(config),
        admission = m::admission::classify_and_validate(config),
        audit = m::audit_policy::classify_and_validate(config),
        authorization = m::authorization::classify_and_validate(config),
        channel_binding = m::transport::classify_and_validate_binding(config),
        crl_revocation = m::crl_revocation::classify_and_validate_crl(config),
        freshness = m::freshness::classify_and_validate(config),
        request_target = m::request_target::classify_and_validate(config),
        connection_bounds = m::connection_bounds::classify_and_validate(config),
        mcp_transport_contract = m::mcp_transport_contract::classify_and_validate(config),
        trust_document = m::trust_document::classify_and_validate(config),
        client_credential_window = m::client_credential_window::classify_and_validate(config),
        server_identity = server_identity,
    }
}
