// SPDX-License-Identifier: Apache-2.0
//! The classified legal deployment state — layer A.
//!
//! `DeploymentRequest` describes a *requested* deployment. Not every combination of its fields
//! describes a deployment that could exist, and layer A is the closed model of the ones
//! that can: twelve machines, each with its own states, a set of guard-only owners that
//! have invariants without a mode choice, and a small set of relations between them. This
//! module is that model as code — one classifier/validator per owner, and one value
//! carrying what they recognised.
//!
//! **Three layers, and this is only the first.** Layer A asks whether the request is
//! internally coherent; it touches no filesystem, no network, and no crate feature. Layer
//! B asks whether *this executable* can establish the request, and layer C whether the
//! world cooperated. Both belong to materialization. `key_source = env` is a coherent
//! request in a binary that cannot serve it: the plan succeeds and materialization
//! refuses, which is `PlanDecision != RuntimeEvidence` working rather than failing.
//!
//! **The classification is a value, not a step (CF-10).** A validator that recognises
//! `PushNetworked`, checks it, and discards the answer leaves planning to re-derive the
//! same fact from the same fields — two derivations of one deployment fact, free to
//! disagree. So validation returns a [`DeploymentConfigState`], and that is what the plane
//! plans project from.
//!
//! **Layer A must not discard evidence intrinsic to the state it just established.** The
//! same argument that makes the classification a value applies to what proving it
//! produced. Deciding that a deployment is `SharedRedis` *is* deciding that its Redis URL
//! is present; a state that keeps only the verdict leaves planning to fetch the URL back
//! out of the broad request and assert `expect("layer A guarantees this")` — the proof
//! erased and then recovered, one layer along, from a representation weak enough to still
//! say `None`.
//!
//! So a semantic owner retains the facts that constitute its invariant. Two shapes, because
//! layer A has two kinds of owner:
//!
//! - A **state-owning machine** carries its classified state together with the witnesses
//!   intrinsic to inhabiting it. A `Reloading` CRL state without its cadence does not
//!   describe a deployment, so the cadence travels with the state that required it.
//! - A **guard-only owner** has no mode choice and therefore no state enum, but still owns
//!   invariants and resolved values. `DelegatedSigning` is unconditional (ADR-MCPRE-052 is
//!   the only response-signing mode) and still owns the §7 trust-epoch requirement and the
//!   two defaulting rules for the issuer kid and the audience hash. A resolved default is
//!   owned at the layer that owns the rule; downstream there is no knowledge that a
//!   default ever existed.
//!
//! **Two limits keep this from becoming a second `DeploymentRequest`.** A generic deployment
//! parameter stays in `DeploymentRequest` — validated, but not evidence for inhabiting any particular
//! state; `max_clock_skew`, `bind` and the limits are checked and stay put. And a fact
//! already encoded by a variant is *derived*, never stored beside it: `SharedRedis` names
//! the tier, so carrying a tier field too would create two authorities free to disagree,
//! and the impossible pairing becomes representable again.
//!
//! **This is not a normalized plan either.** Consumer-specific shaping is still planning's
//! job. The progression is `DeploymentRequest` (requested values) → `DeploymentConfigState` (semantic
//! state plus its own evidence) → `Plan` (one consumer's intent), and each stage means
//! strictly more than the last — without any of them saying "the previous stage promised
//! this".

pub mod admission;
pub mod audit_policy;
pub mod authorization;
mod channel_binding_effects;
pub mod channel_credential_custody;
pub mod channel_key_material;
pub mod client_credential_window;
pub mod connection_bounds;
pub mod continuation_control;
pub(crate) mod coordinate;
pub mod credential_currency_bound;
pub mod crl_revocation;
pub(crate) mod cross_machine;
pub mod custody;
pub mod delegated_signing;
pub mod evidence;
pub mod freshness;
pub mod in_flight_limit;
pub mod key_file_access;
pub(crate) mod kms_endpoint;
pub mod mcp_transport_contract;
pub mod replay;
pub mod replica_clock;
pub mod request_target;
pub mod server_identity;
pub mod topology;
pub mod transport;
pub mod trust_document;
pub mod trust_revocation;
pub mod validation;

pub use admission::{AdmissionAvailability, AdmissionPosture, AdmissionState, EnforcedAdmission};
pub use audit_policy::AuditState;
pub use authorization::{AuthorizationState, EnforcedAuthorization};
pub(crate) use channel_binding_effects::ChannelBindingEffects;
pub use channel_credential_custody::ChannelCredentialCustodyState;
pub use channel_key_material::ChannelKeyMaterial;
pub use client_credential_window::ClientCredentialWindow;
pub use connection_bounds::ConnectionBounds;
pub use continuation_control::ContinuationControlState;
pub use credential_currency_bound::{credential_currency_bound, CredentialCurrencyBound};
pub use crl_revocation::CrlRevocationState;
pub use custody::{AwsCredentialMode, CustodyMaterial, CustodyState, PrivateKeyExposure};
pub use delegated_signing::DelegatedSigningFacts;
pub use evidence::{RetentionState, VerifiedContextState};
pub use freshness::FreshnessWindow;
pub use in_flight_limit::{InFlightLimitBasis, InFlightLimitRequest};
pub use key_file_access::KeyFileAccessPolicy;
pub use key_file_access::{foreign_owner, FOREIGN_OWNER};
pub use mcp_transport_contract::McpTransportContractState;
pub use replay::ReplayState;
pub use replica_clock::ReplicaClockDivergence;
pub use request_target::RequestTarget;
pub use topology::{DeploymentTopology, ShardTopologyRequest};
pub use transport::ChannelBindingState;
pub use trust_document::TrustDocumentSource;
pub use trust_revocation::TrustRevocationState;

/// What layer A recognised: each machine's state, and each guard-only owner's facts.
///
/// Constructible only inside `config_state`, and its only production producer is
/// `validation::validate_configuration`, so holding one outside this module is evidence that
/// every owner here was checked against its own required/optional/forbidden/guard columns
/// and that the cross-machine relations hold between them.
///
/// It holds one field per owner; an owner that is not here yet
/// is one whose legality still lives in the residual clause list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentConfigState {
    /// The recognised states themselves. One field rather than a copy of every field in
    /// [`RecognisedStates`]: the two shapes were identical, and a state added to one had to
    /// be transcribed into the other twice — a per-machine cost that bought nothing, since
    /// the only difference between them was ever the claim attached, not the contents.
    /// Private, as are the inner value's fields, so only `config_state` and its descendants can reach them.
    states: RecognisedStates,
}

/// The recognised states, as one argument, so adding a machine is a change in one place
/// rather than in every signature between the validator and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecognisedStates {
    admission: AdmissionState,
    authorization: AuthorizationState,
    audit: AuditState,
    channel_binding: ChannelBindingState,
    client_credential_window: ClientCredentialWindow,
    connection_bounds: ConnectionBounds,
    continuation_control: ContinuationControlState,
    crl_revocation: CrlRevocationState,
    custody: CustodyState,
    delegated_signing: DelegatedSigningFacts,
    freshness: FreshnessWindow,
    in_flight_limit: InFlightLimitBasis,
    key_file_access: KeyFileAccessPolicy,
    mcp_transport_contract: McpTransportContractState,
    replay: ReplayState,
    request_target: RequestTarget,
    retention: RetentionState,
    server_identity: server_identity::ServerIdentityFacts,
    shard_topology: ShardTopologyRequest,
    channel_credential_custody: ChannelCredentialCustodyState,
    topology: DeploymentTopology,
    trust_document: TrustDocumentSource,
    trust_revocation: TrustRevocationState,
    verified_context: VerifiedContextState,
}

impl DeploymentConfigState {
    /// Assemble the classified state. Private to `config_state`: the only production producer is
    /// `validation::validate_configuration`, because the value's meaning is "these states were checked".
    fn new(states: RecognisedStates) -> Self {
        Self { states }
    }

    /// Whether a workload admission gate applies, how strictly, and — when it does — the
    /// authority and shared record it was found inhabitable by.
    pub fn admission(&self) -> &AdmissionState {
        &self.states.admission
    }

    /// Which authorization authority this deployment installs, and the decision profile it
    /// accepts when it installs one.
    pub fn authorization(&self) -> &AuthorizationState {
        &self.states.authorization
    }

    /// Where the per-request security record goes.
    pub fn audit(&self) -> AuditState {
        self.states.audit
    }

    /// How a verified request signer is bound to the authenticated channel.
    pub fn channel_binding(&self) -> ChannelBindingState {
        self.states.channel_binding
    }

    /// Offline client-certificate revocation.
    pub fn crl_revocation(&self) -> &CrlRevocationState {
        &self.states.crl_revocation
    }

    /// Whether exchanges are retained for later SCITT statements.
    pub fn retention(&self) -> &RetentionState {
        &self.states.retention
    }

    /// What the PEP asserts to the inner server about the caller.
    pub fn verified_context(&self) -> VerifiedContextState {
        self.states.verified_context
    }

    /// Whether multi-round-trip flows resolve across replicas, and nothing about replay:
    /// the two were one field until CF-12 and are two facts.
    pub fn continuation_control(&self) -> &ContinuationControlState {
        &self.states.continuation_control
    }

    /// Where admitted nonces live. Both variants are shared — a node-local replay store is
    /// not a state a deployment can be in.
    pub fn replay(&self) -> &ReplayState {
        &self.states.replay
    }

    /// The accepted temporal uncertainty, and what each mechanism derives from it.
    ///
    /// One fact with two consumers: the RFC 9421 acceptance window and the replay retention
    /// horizon. They read projections of the same value rather than the same raw field.
    pub fn freshness(&self) -> FreshnessWindow {
        self.states.freshness
    }

    /// The configured `@target-uri`, absolute by construction: what the signature base and
    /// the audience cover, and the origin form every request's arrival path is checked against.
    pub fn request_target(&self) -> &RequestTarget {
        &self.states.request_target
    }
    /// Which basis the admission limit is expressed in, with the default already applied.
    ///
    /// A resolved fact rather than a posture: the control is on in both variants, and the
    /// two differ only in the altitude the operator stated it at.
    pub fn in_flight_limit(&self) -> InFlightLimitBasis {
        self.states.in_flight_limit
    }

    /// The five bounds on one connection's life, every one of them in force.
    pub fn connection_bounds(&self) -> ConnectionBounds {
        self.states.connection_bounds
    }

    /// Whether the MCP transport/version contract is asserted, and for which versions.
    pub fn mcp_transport_contract(&self) -> &McpTransportContractState {
        &self.states.mcp_transport_contract
    }

    /// Where the response-signing key lives.
    pub fn custody(&self) -> &CustodyState {
        &self.states.custody
    }

    /// What was established about delegated response signing — the epoch every credential
    /// is minted under, and the two values whose defaulting rule this layer owns.
    pub fn delegated_signing(&self) -> &DelegatedSigningFacts {
        &self.states.delegated_signing
    }

    /// This deployment's own actor identity, derived once.
    ///
    /// Consumers take it rather than assembling one from `trust_domain`, `server_signer`
    /// and a `"server"` literal — which is what two of them used to do.
    pub fn server_identity(&self) -> &server_identity::ServerIdentityFacts {
        &self.states.server_identity
    }

    /// Whether the TLS handshake key can leave the device it lives on.
    pub fn channel_credential_custody(&self) -> &ChannelCredentialCustodyState {
        &self.states.channel_credential_custody
    }

    /// Whether this deployment is one node or one replica of several.
    pub fn topology(&self) -> DeploymentTopology {
        self.states.topology
    }

    /// The serving-shard shape as the operator stated it. Not a count: the host resolves
    /// `Auto` into one.
    pub fn shard_topology(&self) -> ShardTopologyRequest {
        self.states.shard_topology
    }

    /// Which key-file permission postures this deployment accepts.
    ///
    /// The policy answers whether a posture is refused; composition never receives the
    /// flag and re-derives the rule around it.
    pub fn key_file_access(&self) -> KeyFileAccessPolicy {
        self.states.key_file_access
    }

    /// How long a client credential authorizes traffic, and how long one connection may
    /// serve on a single handshake — one fact, because the second is what makes the first
    /// a statement about requests.
    pub fn client_credential_window(&self) -> ClientCredentialWindow {
        self.states.client_credential_window
    }

    /// Which document the request-signer set is read from.
    ///
    /// The locator's own authority, so a plan pairs a revocation posture with a document
    /// both owners recognised rather than with whatever string reached the plan.
    pub fn trust_document(&self) -> &TrustDocumentSource {
        &self.states.trust_document
    }

    /// The trust-revocation state — the authority both `TrustPlan` and `SigningPlan`
    /// consume rather than each re-deriving from `trust_epoch_redis_url` (CF-09).
    pub fn trust_revocation(&self) -> &TrustRevocationState {
        &self.states.trust_revocation
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    /// What one classifier recognised for a fixture its `what` names as legal.
    fn recognised<T, V>(outcome: (Option<T>, V), what: &str) -> T {
        outcome.0.expect(what)
    }

    /// A push-tier trust-revocation posture backed by a networked epoch store.
    fn networked_push_revocation() -> TrustRevocationState {
        test_support::revocation_posture(
            crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
            Some(5),
            Some(("redis://127.0.0.1:6379", "mcp-re:trust:epoch")),
        )
    }

    /// Every owner's recognised state, built through the real classifiers.
    fn recognised_states() -> RecognisedStates {
        let legal = test_support::legal_config();
        let delegated = delegated_signing::classify_and_validate(&legal).0;
        RecognisedStates {
            admission: recognised(
                admission::classify_and_validate(&test_support::enforcing_admission_config()),
                "the enforcing fixture names an admission authority",
            ),
            authorization: recognised(
                authorization::classify_and_validate(&legal),
                "the legal fixture installs no authorization authority",
            ),
            audit: AuditState::Stderr,
            channel_binding: ChannelBindingState::ExactUriSan,
            freshness: recognised(
                freshness::classify_and_validate(&legal),
                "the legal fixture names a bounded freshness window",
            ),
            server_identity: recognised(
                server_identity::classify_and_validate(&legal, delegated.as_ref()),
                "the legal fixture has an identity",
            ),
            key_file_access: key_file_access::classify(&legal),
            topology: topology::classify(&legal).0,
            shard_topology: topology::classify(&legal).1,
            in_flight_limit: InFlightLimitBasis::PerCore {
                requests: std::num::NonZeroUsize::new(256).expect("non-zero"),
            },
            continuation_control: recognised(
                continuation_control::classify_and_validate(
                    &test_support::shared_continuation_config(),
                ),
                "a legal locator names a state",
            ),
            crl_revocation: test_support::crl_posture(&["/crl.pem"], Some(300)),
            client_credential_window: recognised(
                client_credential_window::classify_and_validate(&legal),
                "the legal fixture names a bounded credential window",
            ),
            connection_bounds: recognised(
                connection_bounds::classify_and_validate(&legal),
                "the legal fixture names bounded connections",
            ),
            trust_document: recognised(
                trust_document::classify_and_validate(&legal),
                "the legal fixture names a trust document",
            ),
            custody: test_support::custody_pkcs11(),
            mcp_transport_contract: recognised(
                mcp_transport_contract::classify_and_validate(
                    &test_support::versioned_transport_config(),
                ),
                "the versioned fixture names an accepted version",
            ),
            delegated_signing: delegated.expect("the legal fixture names a trust epoch"),
            replay: recognised(
                replay::classify_and_validate(&test_support::legal_linearizable_config()),
                "the linearizable fixture names a CP store endpoint",
            ),
            request_target: RequestTarget::new("https://proxy.internal:8600/mcp")
                .expect("an absolute target"),
            retention: test_support::retention_at("/var/lib/mcp-re/evidence".to_string()),
            channel_credential_custody: test_support::channel_custody_delegated_pkcs11("tls"),
            trust_revocation: networked_push_revocation(),
            verified_context: VerifiedContextState::Trusted,
        }
    }

    #[test]
    fn the_state_carries_what_the_planes_would_otherwise_re_derive() {
        let state = DeploymentConfigState::new(recognised_states());
        assert!(state.trust_revocation().has_networked_epoch());
        assert_eq!(state.custody().exposure(), PrivateKeyExposure::NonExporting);
        assert_eq!(
            state.channel_credential_custody().exposure(),
            PrivateKeyExposure::NonExporting
        );
        // CF-12's negative control, at the level of the value itself: a linearizable
        // replay store and a shared continuation store are independently expressible.
        assert_eq!(
            state.replay().durability_tier(),
            crate::replay_tier::ReplayDurabilityTier::Linearizable
        );
        assert!(state.continuation_control().is_shared());
        // Every machine layer A names is represented exactly once, including the ones
        // that cannot be misconfigured: the value states the whole posture, not the part
        // that needed checking.
        assert!(state.admission().is_enforced());
        assert_eq!(state.audit(), AuditState::Stderr);
        assert_eq!(state.channel_binding(), ChannelBindingState::ExactUriSan);
        assert_eq!(state.crl_revocation().reload_cadence_secs(), Some(300));
        assert!(state.retention().is_on());
        assert!(state.verified_context().asserts_inner_channel_isolation());
    }
}
