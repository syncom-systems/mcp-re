//! Serve orchestration for the `mcp-re-proxy` binary, in the LIBRARY so it is
//! testable in-process (the binary is a thin shim over [`run`]).
//!
//! The composition root. It establishes the planes that own the runtime's resources
//! (ADR-MCPRE-056 §8), assembles the RFC 9421 serving PEP over them, hands the whole graph
//! to [`crate::materialized_runtime::MaterializedRuntime`], and serves until the caller
//! flips `shutdown`. It decides as little as possible: what it branches on is either a
//! named rule in [`crate::startup_plan`] or a plane's own answer.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::config_state::validation::ValidatedDeployment;
use crate::deployment_request::DeploymentRequest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

/// Build the serving [`crate::ActorResolver`] — the trust seam the RFC 9421 PEP
/// consults for every signature it verifies (slot discipline, MCPRE-100).
///
/// The Response slot answers only for the server identity's own keyid — the resolved
/// issuer kid — from the root/issuer public key held at build time: that key is the
/// deployment's trust anchor, revoked by root rotation rather than by a trust-store entry.
/// The identity is the `ServerIdentity` owner's fact, so the actor stamped on every
/// Response slot, its keyid, and the trust domain of every client actor are read from the
/// one value that owner derived, never supplied beside it.
///
/// The Request slot resolves through `request_trust` — the ADR-MCPS-021
/// revocation-tier resolver — on EVERY request. `trust_store` supplies only the
/// `kid -> signer` identity coordinate; deliberately not the key, since caching the
/// key here would re-freeze trust at process start and silently bypass the tier. It
/// is read through the SNAPSHOT rather than a captured `HashMap` for the same reason:
/// a kid removed from the trust file has to leave the request-signer set at the same
/// instant it stops resolving, or the two disagree for a whole reload cadence.
/// Every non-active outcome (`Revoked`, `NotFound`, `MalformedKey`, `Unavailable`)
/// yields no actor, which the verifier surfaces as `actor_binding_failed`; an
/// operational failure is never softened into an allow.
pub fn build_actor_resolver(
    signers: crate::reloading_trust::SignerDirectory,
    request_trust: Arc<dyn mcp_re_core::TrustResolver + Send + Sync>,
    server: crate::config_state::server_identity::ServerIdentityFacts,
    response_pub: mcp_re_core::VerificationKey,
) -> crate::ActorResolver {
    Box::new(move |kid: &str, slot: SignerSlot| match slot {
        SignerSlot::Response if kid == server.actor().keyid => {
            ResolverOutcome::Resolved(Box::new(ResolvedActor {
                identity: server.actor().clone(),
                verification_key: response_pub.clone(),
                slot,
            }))
        }
        SignerSlot::Request => {
            // An unknown kid is a definitive negative from a healthy resolver.
            let Some(signer) = signers.signer_for(kid) else {
                return ResolverOutcome::NotTrusted;
            };
            // C079: `.ok()?` used to throw this error away, so a store OUTAGE and an
            // unknown keyid became the same observation and the outage was reported as
            // `actor_binding_failed`. `mcp-re-core` has always modelled the difference
            // (`TrustResolverError::Unavailable`); it simply could not cross the seam.
            // Both still fail closed — only the reported reason changes.
            let key = match request_trust.resolve(&signer, kid) {
                Ok(key) => key,
                Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {
                    return ResolverOutcome::Unavailable
                }
                Err(_) => return ResolverOutcome::NotTrusted,
            };
            ResolverOutcome::Resolved(Box::new(ResolvedActor {
                identity: server.client_actor(signer, kid),
                verification_key: key,
                slot,
            }))
        }
        _ => ResolverOutcome::NotTrusted,
    })
}

/// How a deployment arrives here (argv, code, or an embedder with providers), and what
/// every exit discharges.
mod entry;
pub use entry::{run, run_request, run_with};

/// The startup readings and the value every stage runs against.
mod boot;
/// The serving proxy and its optional capabilities.
mod capabilities;
/// The trust, replay, inner and signing stages.
mod planes;
/// The serving path proper.
mod serving;
/// The transport stages.
mod transport;
pub(crate) use serving::serve_fleet;

use boot::{Preflight, Startup};

/// The serving path proper. Reachable only with a [`crate::config_state::validation::ValidatedDeployment`], which
/// is the whole point: there is no route into it that skips the guards.
///
/// The sequence below IS the startup transcript's order, and that order is behaviour:
/// `tests/startup_transcript/` captures it from the shipped binary and asserts on the
/// sequence — a `Vec`, not a set — because a posture line that moved across the
/// trust/replay boundary would be a real change. Each stage is one named step that either
/// hands back what the next needs or refuses with nothing leaking: after
/// `Startup::begin`, every `?` drops the runtime, which reclaims what is installed in the
/// order it owns (ADR-MCPRE-056 §10; ADR-MCPRE-057 §9).
///
/// Every classification lives in `startup_plan` (pure) or `config_state` (layer A), and every
/// resource with a teardown obligation lives in the plane that owns it. What remains here is
/// the order, and the stages named in [`boot`], [`planes`] and [`capabilities`] are where each
/// step's own rule is written down. Compensating evidence: the startup transcript harness
/// (order, from the real binary), `app_startup_characterization_test` (refusals reachable at
/// this altitude) and the plans' own unit tests.
fn run_validated(
    config: &ValidatedDeployment,
    audit: crate::audit_commitment::AuditPlan,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    let Preflight {
        reading,
        crl_reference,
        roots,
        channel_credential,
    } = boot::preflight(config)?;
    let mut start = Startup::begin(config, shutdown)?;
    let audit = capabilities::establish_audit_commitment(&start, audit)?;

    let seam = planes::install_trust(&mut start, &roots)?;
    let authorization = capabilities::authorization(&mut start)?;
    let replay = planes::materialize_replay(&mut start)?;
    transport::install_tls(&mut start, channel_credential, crl_reference)?;
    let serving = transport::serving_options(&mut start)?;
    let pool = planes::inner_pool(&start)?;
    planes::install_signing(&mut start, roots, &reading)?;

    let proxy = capabilities::serving_proxy(&start, seam, replay, pool)?;
    let proxy = capabilities::with_verifier_policy(&mut start, proxy, serving.binding);
    let proxy = capabilities::with_audit_and_retention(&mut start, proxy, audit)?;
    let proxy = capabilities::with_correlation(&mut start, proxy, authorization)?;
    let proxy = capabilities::with_admission(&mut start, proxy)?;
    // Every optional capability has now stated its posture. Serving with an incomplete one is
    // refused in EVERY build profile (ADR-MCPRE-056 §5.4): the transcript is this deployment's
    // statement of which security controls are running, and an operator must not read a list
    // that silently omits an entry.
    start.posture.assert_complete()?;

    // Composed BEFORE the runtime exists: `--bind` resolution can fail, and a failure after
    // `finish` would drop a materialized runtime instead of tearing it down in the order it
    // owns — the one thing that type is for.
    let fleet_cfg = fleet_config(
        config.config(),
        start.sizing.topology,
        start.sizing.in_flight_limit,
    )?;
    start.building.install_proxy(proxy)?;
    // `MaterializationSucceeded` is applied INSIDE `finish`, after every required resource has
    // been taken, so a `Materialized` lifecycle cannot exist over an incomplete graph.
    let runtime = start.building.finish()?;
    runtime.serve(serving.fleet, fleet_cfg)
}

/// The serving topology this deployment asked for, with `--bind` resolved.
///
/// The fleet's whole input. Composed here rather than inside serving because resolving a
/// bind locator is a name lookup — an environment reading — and because it is the last
/// place that legitimately holds the deployment request: what serving needs is a topology,
/// and handing it the request instead would give it every other field as well.
///
/// The topology and the admission basis arrive as their owners' values and are carried
/// whole: the fleet applies the share rule, the root does not.
fn fleet_config(
    values: &DeploymentRequest,
    topology: crate::async_fleet::ResolvedTopology,
    in_flight: crate::config_state::InFlightLimitBasis,
) -> Result<crate::async_fleet::FleetConfig, String> {
    use std::net::ToSocketAddrs;

    let addr = values
        .bind
        .to_socket_addrs()
        .map_err(|e| format!("resolve --bind {}: {e}", values.bind))?
        .next()
        .ok_or_else(|| format!("--bind {} resolved to no address", values.bind))?;

    Ok(crate::async_fleet::FleetConfig {
        addr,
        topology,
        listen_backlog: crate::async_fleet::DEFAULT_LISTEN_BACKLOG,
        in_flight,
    })
}

// EVERY TARGET (r12 R12-627). The `unix` half was for the key-file permission controls, and
// they left with the authority — the arm that genuinely needs unix now carries its own gate.
// Keeping the qualifier would compile these target-independent claims to ZERO tests elsewhere.
#[cfg(test)]
mod tests {
    use crate::config_state::test_support::config_with;

    const BATCH: u64 = 2000;
    const CHILD_MARKER: &str = "MCP_RE_AUDIT_FLUSH_TEARDOWN_CHILD";
    const TEST_NAME: &str = "app::tests::\
                             a_record_enqueued_immediately_before_teardown_still_reaches_stderr";

    /// The child's scenario: enqueue a batch of attributed records, run `app::run` on a
    /// config the validation boundary refuses, and exit the instant it returns.
    fn enqueue_batch_then_exit() -> ! {
        // A config the validation boundary refuses, so `run` returns without opening a
        // socket. The route out does not matter — the drain is on all of them.
        let mut config = config_with("file", "/seed", "/tls.key");
        config.target_uri = String::new();

        // Attributed records, so the unattributed ceiling cannot drop any of them and
        // an absent seq means "lost at exit" rather than "refused by the queue".
        let sink = crate::audit_sink::StderrAuditSink::open()
            .expect("the OS CSPRNG yields an incarnation");
        let audit: crate::audit_sink::MaybeAuditSink = Some(std::sync::Arc::new(sink));
        for i in 0..BATCH {
            crate::audit_record::record_to(
                &audit,
                None,
                crate::audit_record::AuditSubject::request_accepted(
                    &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                    crate::admission_enforcer::AdmissionFacet::NotConfigured,
                ),
                Some("teardown-actor".to_string()),
                200,
                i as i64,
            );
        }
        let _ = super::run_request(
            config,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        // No unwinding, no flush of anything else: whatever the writer has not written
        // by now is lost, which is the condition under test.
        std::process::exit(0);
    }

    /// Re-invoke this test binary on the one scenario, marked as the child.
    fn run_scenario_in_child() -> std::process::Output {
        std::process::Command::new(
            std::env::current_exe().expect("the test binary re-invokes itself"),
        )
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(CHILD_MARKER, "1")
        .output()
        .expect("the child scenario runs")
    }

    /// `--exact` with a name nothing matches selects ZERO tests and exits 0, so the
    /// scenario would silently not run and the drain assertion would fail with a
    /// message about flushing. `TEST_NAME` is a literal that no compiler check keeps in
    /// step with this module's path, so confirm the child actually ran the scenario.
    /// The child `exit`s before libtest prints its summary — that is the point of the
    /// scenario — so the evidence it ran is the line libtest prints on the way IN.
    fn assert_child_ran_the_scenario(child: &std::process::Output) {
        let ran = String::from_utf8_lossy(&child.stdout);
        assert!(
            ran.contains("running 1 test"),
            "the child ran no test: {TEST_NAME:?} matches nothing in this binary. Fix the \
             name before reading anything into the drain assertion.\n{ran}"
        );
    }

    fn assert_batch_drained(stderr: &str) {
        let last = format!("audit seq={} ", BATCH - 1);
        assert!(
            stderr.contains(&last),
            "the record enqueued last before teardown never reached stderr: no {last:?} in \
             the child's output. The audit writer is detached, so an unflushed queue dies \
             with the process and the decisions taken last are neither recorded nor \
             reported missing."
        );
        // The first record is the control: it proves the child really did emit the batch,
        // so a missing tail above is a lost drain rather than a scenario that never ran.
        assert!(
            stderr.contains("audit seq=0 "),
            "the child emitted no audit records at all, so the assertion above proved \
             nothing: {stderr}"
        );
        assert!(
            stderr.contains("audit stream drained at shutdown"),
            "shutdown must STATE which of the two audit outcomes happened, and this run \
             drained: {stderr}"
        );
    }

    /// The run's stream opens with a start line naming the run, and the records and the
    /// shutdown line carry that same run: a collector partitions on it, and a run with a
    /// start line and no shutdown line ended with an unknown tail.
    fn assert_stream_names_one_run(stderr: &str) {
        let run = stderr
            .lines()
            .find_map(|line| line.strip_prefix("mcp-re-proxy: audit stream started run="))
            .unwrap_or_else(|| panic!("the stream never stated its start: {stderr}"));
        assert!(
            stderr.contains(&format!("audit seq=0 run={run} ")),
            "{stderr}"
        );
        assert!(
            stderr.contains(&format!("audit stream drained at shutdown run={run}:")),
            "{stderr}"
        );
    }

    /// R8-C123 (G10's finding, this group's call site): a record handed to the audit
    /// writer immediately before teardown must still reach stderr.
    ///
    /// The writer thread is DETACHED, so nothing joins it: at process exit whatever it
    /// had not yet written is gone, and a shutdown under load loses precisely the
    /// decisions taken last. That is the did-it-get-recorded-or-not collapse — the
    /// records are neither present nor reported missing, because the drop counter only
    /// counts what the QUEUE refused, not what the process exited on top of.
    /// [`crate::audit_sink::drain`] exists to close it, and this is its production
    /// caller.
    ///
    /// The drain owner's own tests assert what the two outcomes MEAN. This one asserts
    /// something only the composition root can: that `run` discharges the obligation on
    /// every route out of it.
    ///
    /// # Why a child process
    ///
    /// The property is "observable AFTER teardown", and teardown means the process is
    /// gone. Asserting it in-process would only assert that a background thread got
    /// around to the write — which it would, given any pause, with or without the flush.
    /// So the scenario runs in a child that enqueues a batch and then `exit`s the instant
    /// `app::run` returns: no destructors, no grace, the detached writer killed where it
    /// stands. With the drain in place every record is on stderr before `run` returns;
    /// without it the tail of the batch dies with the child, which is what the parent
    /// checks by looking for the LAST sequence number rather than any of them.
    #[test]
    fn a_record_enqueued_immediately_before_teardown_still_reaches_stderr() {
        if std::env::var_os(CHILD_MARKER).is_some() {
            enqueue_batch_then_exit();
        }

        let child = run_scenario_in_child();
        assert_child_ran_the_scenario(&child);
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert_batch_drained(&stderr);
        assert_stream_names_one_run(&stderr);
    }

    /// R10-F1. The serving path's channel-binding effects are a function of the state the
    /// `ChannelBinding` owner recognised — never of the raw selectors it classified.
    ///
    /// A verified request subject, through the one producer. The composition root's own
    /// controls need an operand, not a relation.
    fn binding_subject() -> crate::communication_assurance::VerifiedRequestSubject {
        crate::communication_assurance::request_peer_binding::http_profile_adapter::subject_for_test(
            &mcp_re_http_profile::ResolvedActor {
                identity: mcp_re_http_profile::ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:agent-1".into(),
                    keyid: "key-a".into(),
                },
                verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[3u8; 32]).public_key(),
                slot: mcp_re_http_profile::SignerSlot::Request,
            },
        )
    }

    /// The two halves of one decision are checked together: which SAN the identity is read
    /// from, and that the request signer is compared with it at all.
    ///
    /// The `expected_field` column is LOAD-BEARING (r11 R11-129): it used to be bound to
    /// `_` and asserted nothing, so the control read as covering which certificate field
    /// the seam reads while establishing nothing about it. It is now driven through the
    /// production chain — `IdentityPolicy` -> `CertificateIdentityPolicy` -> `selects()`
    /// -> `IdentitySource` — which is the relation r11 R11-127 worried could disagree with
    /// the state. It cannot: it is a total function of the policy this projection installs.
    #[test]
    fn the_channel_binding_effects_are_a_function_of_the_recognised_state() {
        use crate::communication_assurance::CertificateIdentityPolicy;
        use crate::config_state::transport::classify_and_validate_binding;
        use crate::config_state::ChannelBindingState;
        use crate::transport::IdentityPolicy;

        for (source, expected_state, expected_policy, expected_field) in [
            (
                IdentityPolicy::UriSan,
                ChannelBindingState::ExactUriSan,
                IdentityPolicy::UriSan,
                CertificateIdentityPolicy::UriSan,
            ),
            (
                IdentityPolicy::DnsSan,
                ChannelBindingState::ExactDnsSan,
                IdentityPolicy::DnsSan,
                CertificateIdentityPolicy::DnsSan,
            ),
        ] {
            let mut config = config_with("file", "/seed", "/key");
            config.peer_identity =
                crate::deployment_request::PeerIdentityEvidenceRequest::channel_credential(source);
            let (state, refusals) = classify_and_validate_binding(&config);
            assert!(refusals.is_empty(), "{source:?} refused: {refusals:?}");
            assert_eq!(state, Some(expected_state));

            let effects = expected_state.serving_effects();
            assert_eq!(
                effects.identity_policy, expected_policy,
                "{expected_state:?} must read the identity from its own SAN"
            );
            // R11-129/R11-127: the installed policy reaches the AUTHORITY'S vocabulary
            // through the production conversion, so the recognised state and the policy the
            // certificate interpreter runs under cannot disagree. Driven, not restated —
            // this is the same `From` the serving path uses.
            //
            // The last hop — that policy selecting its own certificate FIELD — is
            // `CertificateIdentityPolicy::selects`, private to its owner and controlled
            // there. Widening it to assert the whole chain from here would be a production
            // widening with a test-shaped justification.
            assert_eq!(
                CertificateIdentityPolicy::from(effects.identity_policy),
                expected_field,
                "{expected_state:?} must run the interpreter under its own policy"
            );
            // What the composition root owns is WHICH binding it installs and which SAN
            // the identity is read from. Since ADR-MCPRE-064 Slice 4 the relation itself
            // takes two semantic products built from a real handshake, so the equal /
            // unequal claims live with the authority — `transport::tests::
            // exact_match_binds_a_peer_and_a_request_actor_that_name_one_principal` and its
            // negative. What stays here is the fail-closed direction, which is a property
            // of the installed binding rather than of any peer.
            assert!(
                effects.binding.bind(None, binding_subject()).is_err(),
                "{expected_state:?} must refuse a request presenting no authenticated peer"
            );
        }
    }

    /// The fleet's input is the owners' values, carried whole, and the resolved bind.
    #[test]
    fn the_fleet_config_carries_the_owners_values_and_resolves_the_bind() {
        let config = config_with("file", "/seed", "/key");
        let basis = crate::config_state::in_flight_limit::classify(&config);
        let (_, shard_topology) = crate::config_state::topology::classify(&config);
        let topology = crate::async_fleet::ResolvedTopology::resolve(shard_topology);
        let fleet = super::fleet_config(&config, topology, basis)
            .expect("the fixture binds a literal address");

        assert_eq!(fleet.addr, "127.0.0.1:8443".parse().expect("literal"));
        assert_eq!(fleet.topology, topology);
        assert_eq!(fleet.in_flight, basis);
        assert_eq!(
            fleet.listen_backlog,
            crate::async_fleet::DEFAULT_LISTEN_BACKLOG
        );
    }

    /// A bind that resolves to nothing is refused BEFORE the runtime is assembled, so the
    /// failure cannot drop a materialized runtime instead of tearing it down in order.
    ///
    /// The refusal names the flag: a bare address-parse error tells an operator nothing
    /// about which of several address-shaped settings was rejected.
    #[test]
    fn an_unresolvable_bind_is_refused_and_names_the_flag() {
        let mut config = config_with("file", "/seed", "/key");
        config.bind = "missing-a-port".to_string();

        let refusal = super::fleet_config(
            &config,
            crate::async_fleet::ResolvedTopology::resolve(
                crate::config_state::topology::classify(&config).1,
            ),
            crate::config_state::in_flight_limit::classify(&config),
        )
        .expect_err("no port, no socket address");
        assert!(
            refusal.contains("--bind") && refusal.contains("missing-a-port"),
            "the refusal must name the flag and the value: {refusal}"
        );
    }
}
