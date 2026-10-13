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
    // Each machine's answer is one value, `(state, refusals)`, split once below.
    let continuation_control = m::continuation_control::classify_and_validate(config);
    let custody = m::custody::classify_and_validate(config);
    let delegated_signing = m::delegated_signing::classify_and_validate(config);
    let replay = m::replay::classify_and_validate(config);
    let channel_credential_custody = m::channel_credential_custody::classify_and_validate(config);
    let trust_revocation = m::trust_revocation::classify_and_validate(config);
    let admission = m::admission::classify_and_validate(config);
    let authorization = m::authorization::classify_and_validate(config);
    let channel_binding = m::transport::classify_and_validate_binding(config);
    let crl_revocation = m::crl_revocation::classify_and_validate_crl(config);
    let freshness = m::freshness::classify_and_validate(config);
    let connection_bounds = m::connection_bounds::classify_and_validate(config);
    let mcp_transport_contract = m::mcp_transport_contract::classify_and_validate(config);
    let trust_document = m::trust_document::classify_and_validate(config);
    let client_credential_window = m::client_credential_window::classify_and_validate(config);
    // This deployment's own actor identity. It takes the RESOLVED issuer kid rather than
    // re-reading the primitives it defaults from, so the keyid on the identity and the kid
    // the credential chains to are one value (CF-10).
    let server_identity =
        m::server_identity::classify_and_validate(config, delegated_signing.0.as_ref());
    (
        RefusableStates {
            admission: admission.0,
            authorization: authorization.0,
            channel_binding: channel_binding.0,
            client_credential_window: client_credential_window.0,
            freshness: freshness.0,
            connection_bounds: connection_bounds.0,
            continuation_control: continuation_control.0,
            crl_revocation: crl_revocation.0,
            custody: custody.0,
            delegated_signing: delegated_signing.0,
            mcp_transport_contract: mcp_transport_contract.0,
            replay: replay.0,
            server_identity: server_identity.0,
            channel_credential_custody: channel_credential_custody.0,
            trust_document: trust_document.0,
            trust_revocation: trust_revocation.0,
        },
        Refusals {
            admission: admission.1,
            authorization: authorization.1,
            channel_binding: channel_binding.1,
            continuation_control: continuation_control.1,
            crl_revocation: crl_revocation.1,
            custody: custody.1,
            delegated_signing: delegated_signing.1,
            freshness: freshness.1,
            connection_bounds: connection_bounds.1,
            mcp_transport_contract: mcp_transport_contract.1,
            replay: replay.1,
            trust_document: trust_document.1,
            client_credential_window: client_credential_window.1,
            server_identity: server_identity.1,
            channel_credential_custody: channel_credential_custody.1,
            trust_revocation: trust_revocation.1,
        },
    )
}
