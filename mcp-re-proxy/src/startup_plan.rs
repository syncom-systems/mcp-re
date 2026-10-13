// SPDX-License-Identifier: Apache-2.0
//! Pure startup planning: what the proxy INTENDS to build, decided from validated
//! configuration alone (ADR-MCPRE-056 §5.2).
//!
//! Nothing in this module opens a socket, connects to a store, reads a file, spawns a
//! thread or reads the clock. A plan is a description of intent, not an observation — it
//! says "this deployment asked for the linearizable tier over etcd at this endpoint",
//! never "that endpoint answered". Establishing the latter is materialization's job, and
//! keeping the two apart is what lets the configuration matrix be tested entirely in
//! memory instead of by standing up backends.
//!
//! The distinction matters beyond testability. A plan that quietly performed I/O would
//! make "MCP-RE decided to construct X" and "MCP-RE successfully established X"
//! interchangeable claims, and every posture statement derived from them would inherit
//! the confusion.

use crate::config_state::validation::ValidatedDeployment;

/// The replay plan and the store view materialization reads it through.
///
/// Both are owned by the replay machine: the plan is that machine's projection of its own
/// validated state, so it is re-exported here rather than rebuilt from the state's fields.
/// Planning composes the facts the owners state; it does not restate their semantics.
pub use crate::config_state::replay::{PlannedStore, ReplayPlan};

/// A wall-clock reading below this Unix-seconds threshold is treated as a host-clock
/// fault: 2000-01-01 UTC, far below any plausible real deployment time, so a legitimate
/// clock never trips it while a 0/epoch clock always does.
pub const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// Whether `now_unix` indicates the host clock is unset or broken rather than merely
/// inaccurate (audit #94 F5).
///
/// The reading comes from the environment, but deciding that a given reading is a FAULT
/// is a rule, and it is the part that had to be testable: the caller cannot conjure a
/// broken host clock to exercise it. A wall clock at/near the epoch makes every freshness
/// check fail closed, so the whole deployment denies every request; that is safe but
/// indistinguishable from a load or policy problem unless startup names the cause.
///
/// `now_unix()` clamps a pre-epoch `SystemTime` error to 0, so 0 is the sentinel this must
/// catch, and any negative value that ever reached here is a fault by the same argument.
pub fn host_clock_is_faulted(now_unix: i64) -> bool {
    now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS
}

/// The trust plan and the signing plan, produced together: the one producer of both.
///
/// Both planes consume the root issuer kid delegated credentials chain to (ADR-MCPRE-052)
/// and the shared trust epoch (CF-09). Each is read here once, from what layer A decided —
/// the kid from [`DelegatedSigningFacts`](crate::config_state::DelegatedSigningFacts), the
/// epoch from the classified trust-revocation state — and handed to both plans, so trust
/// never enrolls as a request signer a kid other than the one signing mints under, and the
/// two follow one epoch. `SigningPlan`'s constructor is private to this module and
/// `TrustPlan`'s is reached only from here in production.
pub fn response_authority_plans(config: &ValidatedDeployment) -> (TrustPlan, SigningPlan) {
    let response_kid = config.state().delegated_signing().issuer_kid().to_string();
    let epoch = TrustEpochPlan::from_validated(config);
    let trust = TrustPlan::from_validated(config, response_kid.clone(), epoch.clone());
    (
        trust,
        SigningPlan::from_validated(config, response_kid, epoch),
    )
}

/// The trust plan and its reload posture live with their OWNER — the trust subtree —
/// and are re-exported here so no consumer import path breaks.
///
/// ADR-MCPRE-061 §11 / `docs/dev/sealed-owners.md`: a plan produced by an owner lives with
/// that owner, and `startup_plan` re-exports it. Building it here was the planner
/// restating the owner's semantics (R-COMPOSE).
pub use crate::trust_plan::TrustPlan;
pub use crate::trust_plan::TrustReloadPlan;

/// The shared trust-epoch mechanism, interpreted ONCE (CF-09).
///
/// Two planes act on this fact: trust flushes its cache when the epoch advances, and
/// delegated signing mints under the resulting label so an operator's `mcp-re-proxy trust-epoch advance` revokes
/// fleet-wide. They are consumers. Before this type they were two authorities — each
/// reading `--trust-epoch-redis-url`, each defaulting `--trust-epoch-key`, each with its
/// own build refusal — and the only reason they agreed was that they read the same fields
/// in the same way. Nothing made them.
///
/// The key arrives already defaulted by the trust-revocation classification
/// (`config_state::trust_revocation`, the one place `DEFAULT_TRUST_EPOCH_KEY` is applied),
/// and the plan CARRIES that single decision to both consumers: a default applied at two
/// sites is two decisions that happen to coincide.
///
/// The locator is readable only through [`TrustEpochPlan::networked_source`], which asks
/// the build question first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEpochPlan {
    /// No networked source. The trust cache runs at its declared bound, and delegated
    /// signing mints under the bare `--delegated-trust-epoch` label — the honest
    /// single-node shape, not a degraded one.
    NoNetworkChannel,
    /// A networked epoch counter at this location, under this key.
    Redis {
        /// Where the counter lives and the key holding it.
        locator: EpochLocator,
    },
}

/// Where a networked epoch counter lives, and the key holding it (already defaulted).
///
/// Readable only through `TrustEpochPlan::networked_source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochLocator {
    url: String,
    key: String,
}

/// A networked epoch source this build can establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishableEpochSource<'a> {
    url: &'a str,
    key: &'a str,
}

impl<'a> EstablishableEpochSource<'a> {
    /// Where the counter lives.
    pub fn url(&self) -> &'a str {
        self.url
    }

    /// The key holding the counter.
    pub fn key(&self) -> &'a str {
        self.key
    }
}

impl TrustEpochPlan {
    /// Project the plan from the classified trust-revocation state and the validated
    /// locator.
    ///
    /// Infallible: `PushNetworked` is the state that HAS a source, so layer A has already
    /// established both that this deployment may carry one and that it does.
    pub fn from_validated(config: &ValidatedDeployment) -> TrustEpochPlan {
        match config.state().trust_revocation().epoch_source() {
            Some(source) => TrustEpochPlan::Redis {
                locator: EpochLocator {
                    url: source.url().to_string(),
                    key: source.key().to_string(),
                },
            },
            None => TrustEpochPlan::NoNetworkChannel,
        }
    }

    /// The networked source a consumer may connect to: `Err` with the build refusal when
    /// this build cannot establish it, `None` when the plan has no networked source.
    pub fn networked_source(&self) -> Result<Option<EstablishableEpochSource<'_>>, String> {
        if let Some(refusal) = self.unsupported_by_build() {
            return Err(refusal);
        }
        match self {
            TrustEpochPlan::NoNetworkChannel => Ok(None),
            TrustEpochPlan::Redis { locator } => Ok(Some(EstablishableEpochSource {
                url: &locator.url,
                key: &locator.key,
            })),
        }
    }

    /// A networked plan for in-crate tests.
    #[cfg(test)]
    pub(crate) fn redis(url: &str, key: &str) -> TrustEpochPlan {
        TrustEpochPlan::Redis {
            locator: EpochLocator {
                url: url.to_string(),
                key: key.to_string(),
            },
        }
    }

    /// Why THIS BUILD cannot establish the plan, if it cannot — layer B, stated once.
    ///
    /// Both planes refused a configured epoch source in a build without a Redis client,
    /// in two places, with two different messages naming two different consequences. Each
    /// message was true and neither was complete, and which one an operator met was decided
    /// by materialization order. One refusal states both consequences.
    pub fn unsupported_by_build(&self) -> Option<String> {
        match self {
            TrustEpochPlan::NoNetworkChannel => None,
            TrustEpochPlan::Redis { .. } if cfg!(feature = "redis_replay") => None,
            TrustEpochPlan::Redis { .. } => Some(
                "--trust-epoch-redis-url requires a build with the `redis_replay` feature. \
                 Without it the trust cache has no networked invalidation channel, and \
                 delegated credentials would be minted under the bare --delegated-trust-epoch \
                 label — which the trust-epoch kill switch (`mcp-re-proxy trust-epoch \
                 advance`) cannot revoke. Refusing to start (fail closed, ADR-MCPRE-052 §7)"
                    .to_string(),
            ),
        }
    }
}

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
    /// Project the plan from the validated configuration and the two shared decisions.
    ///
    /// Infallible: the epoch source and `0 < overlap < ttl` are layer A's clauses. The kid
    /// and the epoch are passed in, by [`response_authority_plans`] alone.
    fn from_validated(
        config: &ValidatedDeployment,
        response_kid: String,
        epoch: TrustEpochPlan,
    ) -> SigningPlan {
        let values = config.config();
        let facts = config.state().delegated_signing();
        let rotation = facts.rotation_window();
        let identity = config.state().server_identity().actor();
        SigningPlan {
            custody: mcp_re_http_profile::CustodyConfig {
                issuer_kid: response_kid,
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
            epoch,
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

/// What the TLS plane establishes for client revocation.
///
/// Owned by the CRL machine and re-exported here: the plan is that machine's projection of
/// its own validated state, not a value planning rebuilds from the state's paths.
pub use crate::config_state::crl_revocation::ClientRevocationPlan;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEstablishmentPlan {
    /// The offline peer-credential revocation posture.
    pub client_revocation: ClientRevocationPlan,
    /// How long a client credential authorizes traffic, and how long one connection may
    /// serve on a single handshake — the pair that makes the exposure window honest.
    pub credential_window: crate::config_state::ClientCredentialWindow,
    /// The capacity of the listener's handshake-signature budget: a global ceiling on the
    /// signing backend, not a per-peer allowance.
    pub handshake_signing: crate::delegated_tls::HandshakeSignCapacity,
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
}

/// What the MRTR continuation store must establish (ADR-MCPS-047, CF-12).
///
/// Owned by the continuation-control machine and re-exported here: the plan is that
/// machine's projection of its own validated state, not a value planning rebuilds from
/// the state's locator. `Disabled` is a posture, not an absence — a deployment that
/// selected no shared store installs no correlation store at all, so it cannot complete a
/// continuation-dependent leg and says so on both legs. A `Shared` plan the runtime cannot
/// establish refuses startup rather than degrading to `Disabled`.
pub use crate::config_state::continuation_control::ContinuationControlPlan;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
    use crate::deployment_request::{
        AttestedIngressRequest, DeploymentRequest, IngressAssertionRequest,
        PeerIdentityEvidenceRequest, PinnedChannelAcknowledgement,
    };

    /// A configuration that gets all the way through parsing AND validation, so the
    /// mutation each test applies is the only thing under test.
    ///
    /// Every path points at something that does not exist. That is deliberate: if
    /// planning ever starts reading the environment, these stop passing.
    fn base_argv(extra: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = [
            "--bind",
            "127.0.0.1:0",
            "--audience",
            "did:web:server-1.mcp.example.com",
            "--server-signer",
            "did:web:server-1.mcp.example.com",
            "--server-key-id",
            "k1",
            "--delegated-trust-epoch",
            "epoch-1",
            "--signing-key-seed",
            "/nonexistent/seed",
            "--tls-cert",
            "/nonexistent/cert",
            "--tls-key",
            "/nonexistent/key",
            "--client-ca",
            "/nonexistent/ca",
            "--trust",
            "/nonexistent/trust",
            "--target-uri",
            "https://localhost/",
            "--mcp-protocol-version",
            "2026-07-28",
            "--trust-domain",
            "example.org",
            "--inner-http-url",
            "http://127.0.0.1:9/mcp",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        argv
    }

    fn parse(extra: &[&str]) -> Result<DeploymentRequest, String> {
        crate::cli::parse_args(&base_argv(extra)).map(ValidatedDeployment::into_inner)
    }

    fn strategy_for(extra: &[&str]) -> PeerIdentityProvenance {
        let mut argv: Vec<&str> = SHARED_REDIS.to_vec();
        argv.extend_from_slice(extra);
        let config = parse(&argv).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        validated
            .state()
            .channel_binding()
            .serving_effects()
            .peer_identity_provenance
    }

    /// A deployable configuration reads identity from the verified peer certificate.
    ///
    /// `DirectTls` is the only arm a `ValidatedDeployment` can select today. The other
    /// belongs to a capability the boundary refuses — see the test below — so this is not
    /// "the default among two" but "the one that exists".
    #[test]
    fn a_deployable_configuration_reads_the_verified_peer_certificate() {
        assert!(matches!(
            strategy_for(&[]),
            PeerIdentityProvenance::ChannelCredential
        ));
    }

    /// The `LbAssertion` arm is unreachable through the boundary, and that is the property
    /// worth pinning.
    ///
    /// It serves the two ingress-assertion modes, and both are refused by
    /// `unsafe_config_violations`, so no command line reaches them — they are retained
    /// capabilities (`docs/AGENT_INSTRUCTIONS.md` §9), not dead vocabulary, and the
    /// distinction is exactly that a decision gates them rather than nothing does.
    ///
    /// The property is asserted at `ValidatedDeployment::try_from` for a request built in
    /// code, the altitude that guards the runtime, for all three non-channel-credential
    /// forms: the argv route is refused earlier by the CLI adapter for attested-ingress
    /// and so never reaches the boundary.
    ///
    /// This asserts the refusal rather than the strategy because that is what makes the
    /// classifier's shape honest: if one ever becomes selectable, this fails and the arm
    /// needs its own coverage rather than acquiring it silently.
    #[test]
    fn the_assertion_arm_is_refused_at_the_boundary() {
        let key = "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg";
        let forms = [
            (
                PeerIdentityEvidenceRequest::Unbound,
                "--transport-binding none",
            ),
            (
                PeerIdentityEvidenceRequest::IngressAssertion(IngressAssertionRequest {
                    verification_keys: vec![("lb-1".into(), key.into())],
                }),
                "--transport-binding lb-assertion",
            ),
            (
                PeerIdentityEvidenceRequest::AttestedIngress(AttestedIngressRequest {
                    asserted_identity_kind: crate::transport::IdentityPolicy::UriSan,
                    attestor_keys: vec![("attestor-1".into(), key.into())],
                    identities: vec!["ingress-1".into()],
                    audience: "https://mcp.example.com/mcp".into(),
                    pinned_channel: PinnedChannelAcknowledgement::acknowledged(),
                }),
                "--transport-binding attested-ingress",
            ),
        ];
        for (form, named) in forms {
            let refusal = refusal_for_mutated(SHARED_REDIS, |c| c.peer_identity = form);
            assert!(
                refusal.contains(named),
                "{named} must be refused at the boundary and named; if it now starts, \
                 `ChannelBindingState::serving_effects` has a reachable arm with no test: {refusal}"
            );
        }
    }

    /// Plan a configuration that came through the parser intact.
    fn plan_for(extra: &[&str]) -> ReplayPlan {
        let config = parse(extra).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        validated.state().replay().materialization_plan()
    }

    /// Why a configuration is not a replay deployment at all.
    ///
    /// `parse_args` runs its own completeness checks, so an incomplete shared tier never
    /// survives the command line. Those checks are not what protects the runtime: `DeploymentRequest`
    /// has public fields and `run` accepts anything that validates, so an embedder that
    /// builds one in code meets only the boundary. Mutating a parsed config reproduces
    /// such a caller exactly — and since layer A now classifies replay, these refusals are
    /// the boundary's, not planning's.
    fn refusal_for_mutated(extra: &[&str], mutate: impl FnOnce(&mut DeploymentRequest)) -> String {
        let mut config = parse(extra).expect("args parse");
        mutate(&mut config);
        ValidatedDeployment::try_from(config).expect_err("the mutation must be refused")
    }

    const SHARED_REDIS: &[&str] = &[
        "--replay-durability-tier",
        "redis-wait-quorum:2:2000",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
    ];

    const SHARED_LINEARIZABLE: &[&str] = &[
        "--replay-durability-tier",
        "linearizable",
        "--cpstore-etcd-endpoint",
        "http://127.0.0.1:2379",
    ];

    /// The in-memory tier never reaches planning, because validation refuses it outright
    /// — it is non-durable, and a restart re-opens a replay window for any still-fresh
    /// captured envelope.
    ///
    /// `ReplayPlan` no longer has a `Memory` variant to reach: it had a full
    /// materialization arm that no configuration could produce. This is pinned so that a
    /// later change which makes validation accept memory has to fail a test rather than
    /// quietly restore a non-durable production tier.
    /// A request that declares no durable replay configuration fails closed.
    ///
    /// The durability tier is the only replay selector, and there is no node-local state to
    /// fall back to, so saying nothing about replay must refuse rather than acquire an
    /// implicit store. Checked at both altitudes because they can disagree: on the command
    /// line, and for a caller that never touched one.
    #[test]
    fn a_request_with_no_durable_replay_configuration_fails_closed() {
        // A command line carrying every other required flag but no replay configuration.
        let from_argv = parse(&[]).expect_err("no replay configuration must not validate");
        assert!(
            from_argv.contains("--replay-durability-tier"),
            "the refusal must name what is missing: {from_argv}"
        );

        // And for a programmatic request, which is the altitude that guards the runtime.
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay.durability = None);
        assert!(
            err.contains("--replay-durability-tier"),
            "a request whose tier is cleared must be refused: {err}"
        );
    }

    #[test]
    fn linearizable_plans_etcd_at_the_declared_endpoint() {
        let plan = plan_for(SHARED_LINEARIZABLE);
        assert_eq!(
            plan.store(),
            PlannedStore::Etcd {
                endpoint: "http://127.0.0.1:2379"
            }
        );
        assert_eq!(
            plan.tier(),
            &crate::replay_tier::ReplayDurabilityTier::Linearizable
        );
    }

    /// The declared WAIT parameters survive planning intact. Materialization sizes the
    /// client response timeout from them BEFORE connecting, so a plan that dropped them
    /// would silently restore the defect where a declared 2000ms wait could never exceed
    /// the redis library's 500ms per-command default.
    #[test]
    fn a_redis_tier_carries_its_url_and_its_wait_parameters() {
        let plan = plan_for(SHARED_REDIS);
        match plan.store() {
            PlannedStore::Redis { url } => {
                assert_eq!(url, "redis://127.0.0.1:6379");
                assert_eq!(plan.tier().wait_quorum_params(), Some((2, 2000)));
            }
            other => panic!("expected a redis plan, got {other:?}"),
        }
    }

    #[test]
    fn a_shared_tier_that_skipped_the_parser_is_refused_without_a_durability_tier() {
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay.durability = None);
        assert!(err.contains("--replay-durability-tier"), "{err}");
    }

    #[test]
    fn a_shared_redis_tier_that_skipped_the_parser_is_refused_without_a_url() {
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay.store = None);
        assert!(err.contains("--replay-redis-url"), "{err}");
    }

    /// The linearizable claim is never silently downgraded to redis or to memory: with no
    /// CPStore endpoint the tier is refused, not resolved to something weaker.
    #[test]
    fn a_linearizable_tier_that_skipped_the_parser_is_refused_without_an_endpoint() {
        let err = refusal_for_mutated(SHARED_LINEARIZABLE, |c| c.replay.store = None);
        assert!(err.contains("--cpstore-etcd-endpoint"), "{err}");
    }

    /// The property that makes the whole layer worth having, asserted rather than left
    /// incidental: a complete networked tier is planned against a TEST-NET-3 host that is
    /// never contacted, from a config whose every file path does not exist. The wall-time
    /// bound is what observes the absence of a connect.
    #[test]
    fn planning_reaches_a_networked_tier_without_contacting_anything() {
        let started = std::time::Instant::now();
        let plan = plan_for(&[
            "--replay-durability-tier",
            "redis-wait-quorum:2:2000",
            "--replay-redis-url",
            "redis://203.0.113.1:6379",
        ]);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "TEST-NET-3 (203.0.113.1) black-holes a TCP connect for tens of seconds, so a \
             planner that dialled the endpoint fails here instead of merely running slowly"
        );
        assert!(matches!(plan.store(), PlannedStore::Redis { .. }));
    }

    /// The explicit issuer kid wins; without one the server key id names the issuer.
    /// Both planes must be handed the SAME answer, which is why it is derived here.
    #[test]
    fn the_issuer_kid_falls_back_to_the_server_key_id() {
        let config = parse(SHARED_REDIS).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        assert_eq!(
            response_authority_plans(&validated).0.response_kid(),
            "k1",
            "with no --delegated-issuer-kid the server key id names the issuer"
        );

        let explicit = parse(&[SHARED_REDIS, &["--delegated-issuer-kid", "root-kms-1"]].concat())
            .expect("args parse");
        let validated = ValidatedDeployment::try_from(explicit).expect("config validates");
        assert_eq!(
            response_authority_plans(&validated).0.response_kid(),
            "root-kms-1"
        );
    }

    // ---- control-runtime selections ---------------------------------------------
    //
    // A capability needs the control runtime exactly when its owner selected a networked
    // store, and its networked arm asks for the runtime itself. Each selection is asserted
    // on its own: the historical defect was one consumer's need being inferred from
    // another's.

    #[test]
    fn only_the_redis_replay_tier_selects_a_networked_store() {
        assert!(matches!(
            plan_for(SHARED_REDIS).store(),
            PlannedStore::Redis { .. }
        ));
        assert!(
            matches!(
                plan_for(SHARED_LINEARIZABLE).store(),
                PlannedStore::Etcd { .. }
            ),
            "the etcd store drives its own requests"
        );
    }

    /// Keyed on its OWN locator, and independent of the replay tier (CF-12).
    ///
    /// This test used to assert that `--replay-redis-url` beside a linearizable tier
    /// switched continuation on. That was the alias: one field naming the replay store
    /// under one tier and the continuation store under another. The configuration it
    /// described is now refused, and the capability it wanted is expressed directly.
    #[test]
    fn continuation_selects_on_its_own_locator_not_the_replay_tier() {
        // The negative control for the split: a CP replay store AND a shared continuation
        // store, which the alias made impossible to state without overloading a field.
        let both = parse(&[
            "--replay-durability-tier",
            "linearizable",
            "--cpstore-etcd-endpoint",
            "http://127.0.0.1:2379",
            "--continuation-control-redis-url",
            "redis://127.0.0.1:6379",
        ])
        .expect("args parse");
        let validated = ValidatedDeployment::try_from(both).expect("independent facts, both legal");
        assert_eq!(
            validated
                .state()
                .continuation_control()
                .continuation_plan()
                .shared_store(),
            Some("redis://127.0.0.1:6379")
        );
        assert!(
            matches!(
                validated.state().replay().materialization_plan().store(),
                PlannedStore::Etcd { .. }
            ),
            "the tier is etcd, so replay itself selects no networked store"
        );

        // And the converse: the replay store's locator no longer reaches continuation.
        let no_continuation = parse(SHARED_LINEARIZABLE).expect("args parse");
        let validated = ValidatedDeployment::try_from(no_continuation).expect("validates");
        assert_eq!(
            validated
                .state()
                .continuation_control()
                .continuation_plan()
                .shared_store(),
            None
        );
    }

    /// The projected endpoint is the continuation store's own locator, character for
    /// character (CF-12).
    ///
    /// Whether a store was selected says nothing about WHICH, so that alone stays true for
    /// an endpoint that is empty or that names the replay store. Two Redis instances configured at
    /// once separate the two: continuations planned against the replay store would be
    /// written where no answer leg reads them, and every cross-replica approval would fail
    /// closed.
    #[test]
    fn the_continuation_plan_carries_its_own_endpoint_verbatim() {
        let config = parse(&[
            "--replay-durability-tier",
            "redis-wait-quorum:2:2000",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--continuation-control-redis-url",
            "redis://127.0.0.1:6380",
        ])
        .expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");

        assert_eq!(
            validated
                .state()
                .continuation_control()
                .continuation_plan()
                .shared_store(),
            Some("redis://127.0.0.1:6380")
        );
        match validated.state().replay().materialization_plan().store() {
            PlannedStore::Redis { url } => assert_eq!(url, "redis://127.0.0.1:6379"),
            other => panic!("expected a redis replay plan, got {other:?}"),
        }
    }

    /// The clean break: the old overloaded configuration is refused at layer A, not
    /// silently reinterpreted as continuation configuration.
    #[test]
    fn the_old_alias_is_refused_rather_than_reinterpreted() {
        let refusal = parse(&[
            "--replay-durability-tier",
            "linearizable",
            "--cpstore-etcd-endpoint",
            "http://127.0.0.1:2379",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
        ])
        .expect_err("the alias is refused");
        assert!(
            refusal.contains("both name the replay store"),
            "the pair is refused where it is still statable — argv: {refusal}"
        );
        assert!(
            refusal.contains("--continuation-control-redis-url"),
            "the refusal must name the setting that replaces the overloaded use: {refusal}"
        );
    }

    // ---- the trust plan (CF-09, CF-10) ------------------------------------------

    /// A push tier with a networked epoch source, which is the only state that plans one.
    const PUSH_NETWORKED: &[&str] = &[
        "--revocation-tier",
        "push:30",
        "--trust-reload-secs",
        "15",
        "--trust-epoch-redis-url",
        "redis://127.0.0.1:6379",
    ];

    fn validated(extra: &[&str]) -> ValidatedDeployment {
        let config = parse(&[SHARED_REDIS, extra].concat()).expect("args parse");
        ValidatedDeployment::try_from(config).expect("config validates")
    }

    /// The epoch is planned from the CLASSIFICATION, and the key is defaulted by the
    /// classification once. The plan carries that decision to both planes, which used to
    /// default it for themselves: two decisions that happened to coincide.
    #[test]
    fn the_epoch_plan_normalizes_the_key_once() {
        assert_eq!(
            TrustEpochPlan::from_validated(&validated(PUSH_NETWORKED)),
            TrustEpochPlan::redis(
                "redis://127.0.0.1:6379",
                crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY
            ),
            "an unset --trust-epoch-key is resolved by the classification and carried by the plan"
        );
        assert_eq!(
            TrustEpochPlan::from_validated(&validated(
                &[PUSH_NETWORKED, &["--trust-epoch-key", "mcp-re:epoch"]].concat()
            )),
            TrustEpochPlan::redis("redis://127.0.0.1:6379", "mcp-re:epoch")
        );
    }

    /// A consumer cannot connect without the build question being asked: the locator has
    /// no accessor except the projection that refuses first.
    #[test]
    fn a_networked_locator_is_readable_only_through_the_build_verdict() {
        let networked = TrustEpochPlan::from_validated(&validated(PUSH_NETWORKED));
        if cfg!(feature = "redis_replay") {
            let source = networked
                .networked_source()
                .expect("this build can establish it")
                .expect("the plan is networked");
            assert_eq!(source.url(), "redis://127.0.0.1:6379");
            assert_eq!(source.key(), crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
        } else {
            let refusal = networked
                .networked_source()
                .expect_err("this build has no Redis client");
            assert!(refusal.contains("redis_replay"), "{refusal}");
        }
        let none = TrustEpochPlan::from_validated(&validated(&[]));
        assert_eq!(none.networked_source(), Ok(None));
    }

    /// Every state that is not `PushNetworked` plans no channel. Asserted across all four
    /// rather than only on the default, because the absence of a channel is the honest
    /// single-node posture and not a failure to configure one.
    #[test]
    fn only_the_networked_push_state_plans_an_epoch_source() {
        for extra in [
            &[][..],
            &["--revocation-tier", "live", "--trust-reload-secs", "5"][..],
            &["--revocation-tier", "push:30", "--trust-reload-secs", "15"][..],
        ] {
            let plan = TrustEpochPlan::from_validated(&validated(extra));
            assert_eq!(
                plan,
                TrustEpochPlan::NoNetworkChannel,
                "{extra:?} planned a channel"
            );
            assert!(
                plan.unsupported_by_build().is_none(),
                "a plan with no channel is establishable by every build"
            );
        }
    }

    /// The layer-B refusal is the PLAN's, so both consumers state the same one. It names
    /// both consequences, because each plane used to name only its own.
    #[test]
    fn the_build_refusal_is_stated_once_and_names_both_consequences() {
        let plan = TrustEpochPlan::from_validated(&validated(PUSH_NETWORKED));
        match (plan.unsupported_by_build(), cfg!(feature = "redis_replay")) {
            (None, true) => {}
            (Some(refusal), false) => {
                assert!(refusal.contains("redis_replay"), "{refusal}");
                assert!(
                    refusal.contains("invalidation"),
                    "the trust consequence must be named: {refusal}"
                );
                assert!(
                    refusal.contains("kill switch"),
                    "the signing consequence must be named: {refusal}"
                );
            }
            (verdict, redis) => panic!("build support {redis} disagreed with {verdict:?}"),
        }
    }

    // ---- the signing plan ----------------------------------------------------------

    /// The issuer kid has ONE derivation, and the plan carries whatever it is handed.
    ///
    /// The defect this closes: the kid was derived twice — by the planner, whose
    /// value the startup transcript prints and which trust excludes from the request-signer
    /// set, and again inside the delegated wiring, which is the one that reached the
    /// credential. Both spelled the same fallback, so they agreed. A deployment could
    /// otherwise have been told it was chaining to one issuer while minting under another.
    ///
    /// Asserted with a kid the configuration does not name, which is only possible because
    /// nothing inside re-derives it.
    #[test]
    fn the_issuer_kid_in_the_credential_is_the_one_that_was_planned() {
        let config = validated(&[]);
        assert_ne!(
            response_authority_plans(&config).0.response_kid(),
            "decided-above"
        );
        let plan = SigningPlan::from_validated(
            &config,
            "decided-above".to_string(),
            TrustEpochPlan::NoNetworkChannel,
        );
        assert_eq!(
            plan.custody().issuer_kid,
            "decided-above",
            "the credential must be minted under the planned issuer, not a re-derived one"
        );
    }

    /// The audience-scope hash defaults to the response audience, once.
    #[test]
    fn the_audience_scope_defaults_to_the_response_audience_and_is_overridable() {
        let (_, plan) = response_authority_plans(&validated(&[]));
        assert_eq!(plan.custody().audience_hash, plan.custody().aud);

        let (_, plan) =
            response_authority_plans(&validated(&["--delegated-audience-hash", "scope-1"]));
        assert_eq!(plan.custody().audience_hash, "scope-1");
        assert_ne!(plan.custody().audience_hash, plan.custody().aud);
    }

    /// CF-09's independence control, on the second consumer: the signing plan cannot be
    /// given an epoch the trust plan does not hold.
    ///
    /// Signing is the plane that landed last, which is exactly when the shortcut is
    /// tempting: take the epoch from the sibling that already has one, or from
    /// configuration through a second reading. Its constructor is private to this module and
    /// its fields are private, so the one producer is the only way to obtain a plan — and
    /// the plan it returns carries the epoch decision the trust plan carries, read once from
    /// the classified state, for a networked source and for none.
    #[test]
    fn the_signing_plan_cannot_be_given_a_different_epoch() {
        for args in [PUSH_NETWORKED, &[] as &[&str]] {
            let config = validated(args);
            let (trust, signing) = response_authority_plans(&config);
            assert_eq!(*signing.epoch(), TrustEpochPlan::from_validated(&config));
            assert_eq!(signing.epoch(), trust.epoch());
        }
        assert!(matches!(
            response_authority_plans(&validated(PUSH_NETWORKED))
                .1
                .epoch(),
            TrustEpochPlan::Redis { .. }
        ));
    }

    /// Both consumers of one decision hold the SAME value — the property CF-09 exists for,
    /// asserted on the producer `app` calls rather than on a re-creation of its wiring.
    #[test]
    fn both_consumers_of_the_epoch_hold_one_decision() {
        let config = validated(PUSH_NETWORKED);
        let (trust, signing) = response_authority_plans(&config);
        // Read through the named projections: a consumer relates the two plans by the facts
        // they publish, not by destructuring either of them.
        assert_eq!(trust.epoch(), signing.epoch());
        assert_eq!(trust.response_kid(), signing.custody().issuer_kid);
        assert_eq!(
            trust.response_kid(),
            config.state().delegated_signing().issuer_kid()
        );
    }

    // ---- the TLS plan --------------------------------------------------------------

    /// Each CRL posture is projected as the VARIANT that carries its own parameters.
    ///
    /// The combinations layer A refuses are not merely unreachable here, they are
    /// unrepresentable: the posture IS the pair, so a consumer cannot hold a cadence
    /// without files or report a cadence the deployment did not set. That is what stops the
    /// plane rediscovering the posture from a `Vec` and an `Option` handed to it side by
    /// side.
    #[test]
    fn each_crl_posture_is_projected_as_its_own_variant() {
        let none = validated(&[])
            .state()
            .crl_revocation()
            .client_revocation_plan();
        assert!(!none.is_enforced());
        assert!(none.paths().is_empty());
        assert_eq!(none.reload_cadence_secs(), None);

        let static_plan = validated(&["--client-crl", "/crl.pem"])
            .state()
            .crl_revocation()
            .client_revocation_plan();
        assert!(static_plan.is_enforced());
        assert_eq!(static_plan.paths(), ["/crl.pem".to_string()]);
        assert_eq!(static_plan.reload_cadence_secs(), None);

        let reloading = validated(&[
            "--client-crl",
            "/crl.pem",
            "--client-crl-reload-secs",
            "300",
        ])
        .state()
        .crl_revocation()
        .client_revocation_plan();
        assert!(reloading.is_enforced());
        assert_eq!(reloading.paths(), ["/crl.pem".to_string()]);
        assert_eq!(reloading.reload_cadence_secs(), Some(300));
    }

    /// Materialization loads the same bytes under both CRL-bearing postures, so the paths
    /// are reachable without matching — but the accessor answers "which files", never
    /// "which posture". An empty result means this posture reads none, not that the
    /// deployment has no revocation configured.
    #[test]
    fn the_paths_accessor_answers_which_files_not_which_posture() {
        assert!(crate::config_state::test_support::crl_plan(&[], None)
            .paths()
            .is_empty());
        for plan in [
            crate::config_state::test_support::crl_plan(&["/a.pem"], None),
            crate::config_state::test_support::crl_plan(&["/a.pem"], Some(60)),
        ] {
            assert_eq!(plan.paths(), ["/a.pem".to_string()]);
        }
    }

    /// The plan carries three classified states, and the credential window is one of them.
    ///
    /// The cert lifetime and the connection age used to travel as two `Option<Duration>`
    /// inputs under a comment saying their relation "was settled at layer A". It was not:
    /// the relation compared the age against the ceiling constant, never against the
    /// configured lifetime. The plan now carries the pair as one owned fact, so the
    /// assertion is about a window rather than about two durations.
    #[test]
    fn the_channel_plan_carries_the_credential_window() {
        let config = validated(&["--max-client-cert-lifetime", "3600"]);
        let plan = ChannelEstablishmentPlan::from_validated(&config);
        assert_eq!(
            plan.credential_window.cert_lifetime(),
            std::time::Duration::from_secs(3600)
        );
        assert!(
            plan.credential_window.connection_age() <= plan.credential_window.exposure_window(),
            "the plan cannot hold a connection age that outlives the credential"
        );
        assert!(!plan.client_revocation.is_enforced());
    }

    /// The operator's handshake-signing capacity reaches the plan the TLS plane builds the
    /// listener from, and stating none leaves the defaults.
    #[test]
    fn the_channel_plan_carries_the_operators_handshake_signing_capacity() {
        use crate::delegated_tls::HandshakeSignCapacity;
        let stated = validated(&[
            "--tls-handshake-sign-rate",
            "250",
            "--tls-handshake-sign-burst",
            "40",
        ]);
        assert_eq!(
            ChannelEstablishmentPlan::from_validated(&stated).handshake_signing,
            HandshakeSignCapacity::new(250, 40).expect("in bounds")
        );
        let unstated = validated(&[]);
        assert_eq!(
            ChannelEstablishmentPlan::from_validated(&unstated).handshake_signing,
            HandshakeSignCapacity::default()
        );
    }

    /// A COMPLETE admission configuration. Setting only `admission` used to be enough
    /// here, which was itself a symptom: the validation boundary did not check admission
    /// at all, so a half-configured gate reached planning. It does now (FF4), and a plan
    /// test must exercise a configuration a deployment could actually hold.
    fn with_admission(
        mut config: crate::deployment_request::DeploymentRequest,
    ) -> crate::deployment_request::DeploymentRequest {
        config.admission = crate::deployment_request::AdmissionRequest::Required(
            crate::deployment_request::AdmissionGateRequest {
                authority_kid: "admission-root-1".to_string(),
                authority_pubkey_b64url: "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg".to_string(),
                store: crate::deployment_request::SharedStoreRequest::redis(
                    "redis://127.0.0.1:6379",
                ),
                availability: crate::deployment_request::AdmissionAvailabilityRequest::FailClosed,
                record_max_age_secs: std::num::NonZeroU64::new(60).expect("nonzero"),
            },
        );
        config
    }

    /// Admission's endpoint is its own. Selecting it independently of replay is what stopped
    /// it being unimplementable on the CP/linearizable tier: the gate is enforced on a tier
    /// whose replay store needs no control runtime.
    #[test]
    fn admission_selects_independently_of_replay() {
        let off = ValidatedDeployment::try_from(parse(SHARED_LINEARIZABLE).expect("parse"))
            .expect("validates");
        assert!(off.state().admission().enforced().is_none());

        let on = with_admission(parse(SHARED_LINEARIZABLE).expect("parse"));
        let on = ValidatedDeployment::try_from(on).expect("validates");
        assert!(on.state().admission().enforced().is_some());
        assert!(
            matches!(
                on.state().replay().materialization_plan().store(),
                PlannedStore::Etcd { .. }
            ),
            "admission must not need the replay tier to have asked first"
        );
    }

    /// The sentinel `now_unix()` produces for a pre-epoch `SystemTime` error, and the
    /// unset-clock reading it stands in for, must both be faults. A predicate that only
    /// caught literal 0 would pass a host reading a few days past the epoch.
    #[test]
    fn an_epoch_or_pre_epoch_clock_reading_is_a_fault() {
        assert!(host_clock_is_faulted(0));
        assert!(host_clock_is_faulted(-1));
        assert!(host_clock_is_faulted(86_400));
        assert!(host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1));
    }

    /// The threshold is far enough below any real deployment time that a correct clock
    /// never trips it — otherwise the warning would fire on every start and stop meaning
    /// anything.
    #[test]
    fn a_plausible_deployment_clock_is_not_a_fault() {
        assert!(!host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS));
        // 2026-01-01 UTC.
        assert!(!host_clock_is_faulted(1_767_225_600));
        assert!(!host_clock_is_faulted(i64::MAX));
    }
}
