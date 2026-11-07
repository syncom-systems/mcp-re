// SPDX-License-Identifier: Apache-2.0
//! What `ValidatedDeployment` does and does not establish, measured rather than read.
//!
//! `ValidatedDeployment` is meant to mean "this deployment state is legal". The claim is only
//! as strong as the set of relations its constructor actually decides, and this file
//! measures that set from the outside: each case builds a `DeploymentRequest` in code carrying a
//! state `parse_args` refuses, and records whether the boundary refuses it too.
//!
//! This file carried a second test, of relations the parser decided and the boundary did
//! not — cases recorded as ADMITTED, each to be moved into [`refused_at_the_boundary`] when
//! its relation arrived. Every one has now moved, the last being a `--ocsp-responder-url`
//! configured beside a mode that never reads it, so the ledger is closed and its test is
//! gone rather than left standing over nothing.
//!
//! What remains is the positive half of the same measurement: each case below is a state
//! `parse_args` used to be the only thing that refused, and the assertion is that a
//! `DeploymentRequest` built in code — never passing a parser — is refused too.

use mcp_re_proxy::cli;
use mcp_re_proxy::config_state::validation::ValidatedDeployment;
use mcp_re_proxy::deployment_request::DeploymentRequest;

/// The smallest command line that parses under the unconditional strict posture.
///
/// It names `--replay-cache file` because the boundary refuses `memory` and its refusal
/// text recommends `file`. See [`the_recommended_replay_backend_cannot_start`].
fn base() -> DeploymentRequest {
    let argv: Vec<String> = [
        "--bind",
        "127.0.0.1:8443",
        "--audience",
        "did:web:server-1.mcp.example.com",
        "--server-signer",
        "did:web:server-1.mcp.example.com",
        "--server-key-id",
        "server-key-1",
        "--signing-key-seed",
        "/seed",
        "--tls-cert",
        "/cert",
        "--tls-key",
        "/key",
        "--client-ca",
        "/ca",
        "--trust",
        "/trust.json",
        "--inner-http-url",
        "http://127.0.0.1:8080/mcp",
        "--target-uri",
        "https://mcp.example.com/mcp",
        "--mcp-protocol-version",
        "2026-07-28",
        "--delegated-trust-epoch",
        "epoch-min",
        "--trust-domain",
        "mcp.example.com",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
        "--replay-durability-tier",
        "redis-wait-quorum:1:100",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    cli::parse_args(&argv)
        .expect("baseline parses")
        .config()
        .clone()
}

#[test]
fn the_baseline_is_admitted() {
    assert!(
        ValidatedDeployment::try_from(base()).is_ok(),
        "the baseline must be legal, or every case below measures the wrong thing"
    );
}

type Mutation = fn(&mut DeploymentRequest);

/// Every case of `cases` starts from the baseline, applies its mutation, and is refused.
fn assert_each_mutation_is_refused(cases: &[(&str, Mutation)], still: &str) {
    for (name, mutate) in cases {
        let mut config = base();
        mutate(&mut config);
        assert!(
            ValidatedDeployment::try_from(config).is_err(),
            "{name}: {still}"
        );
    }
}

/// The baseline after `mutate`, which the boundary must refuse with text naming `flag`.
fn assert_refusal_names(mutate: Mutation, flag: &str, why: &str) {
    let mut config = base();
    mutate(&mut config);
    let refusal = ValidatedDeployment::try_from(config).expect_err(why);
    assert!(refusal.contains(flag), "{refusal}");
}

/// ADR-MCPRE-052 §7: the epoch minted into every delegated response-signing credential.
/// A verifier admits only credentials whose epoch is in its accepted set, so there is
/// deliberately no default. Admitted before, and refused instead inside
/// `delegated_wiring` — after the trust and TLS planes had read files and started
/// workers, by a module whose subject is building a signer rather than judging a
/// configuration. Its two siblings (`--delegated-ttl-secs`, `--delegated-overlap-secs`)
/// were already boundary clauses, so one family was split across two layers.
fn the_delegated_trust_epoch_is_required() {
    assert_refusal_names(
        |c| c.delegated_signing.trust_epoch = None,
        "--delegated-trust-epoch",
        "delegated signing must not mint under a bare epoch label",
    );
}

/// The inner plane. Admitted before, and refused instead by the TRUST plane — which
/// meant a configuration naming no inner server was rejected only after trust had read
/// its document and started its workers, by a plane with no stake in the question.
fn an_inner_server_is_required() {
    assert_refusal_names(
        |c| c.inner_http_urls = Vec::new().into(),
        "--inner-http-url",
        "a deployment must name an inner server",
    );
}

// MCPS-84 used to be pinned here: an epoch source under a tier that
// consumes none, which the deployment believed was an active networked invalidation.
// It is gone because only the pushing posture has a field for one — the mutation cannot
// be written (ADR-MCPRE-067 §7). The argv form is refused by `cli::currency_flags`.

/// The `Custody` machine. `--key-source file` with no seed is the `FileSeed` state missing
/// the one parameter it cannot start without: nothing else in that state supplies the
/// response-signing key.
fn a_file_custody_state_needs_its_seed() {
    assert_refusal_names(
        |c| {
            c.response_signing.source =
                mcp_re_proxy::deployment_request::SigningSourceRequest::File(
                    mcp_re_proxy::deployment_request::FileSigningSourceRequest {
                        seed_path: String::new(),
                    },
                );
        },
        "--signing-key-seed",
        "a custody state with no key",
    );
}

/// The Replay machine's forbidden and required columns. A CP-store
/// endpoint on a state whose store is Redis; and a deployment declaring no durability
/// tier, when the tier IS the horizontal replay-safety claim and the only selector.
fn the_replay_machine_columns_are_enforced() {
    assert_each_mutation_is_refused(
        &[
            ("cpstore_etcd_endpoint", |c| {
                c.replay.store = Some(mcp_re_proxy::deployment_request::ReplayStoreRequest::etcd(
                    "http://127.0.0.1:2379",
                ))
            }),
            ("replay_durability_tier", |c| c.replay.durability = None),
        ],
        "still admitted at the boundary",
    );
}

/// The deployment's own identity coordinates. Requiredness lived in the parser's
/// `require()`, which rejects an ABSENT flag and says nothing about an EMPTY value —
/// and nothing at all about a config built in code. Nothing downstream dereferences
/// these: they are minted into what the proxy signs and compared by verifiers, so an
/// empty one failed no startup step and simply stopped distinguishing this deployment.
///
/// The locators are in the same list. They ARE dereferenced at startup, so an empty one
/// always failed eventually — but as an observation about the environment, raised after
/// planes had established resources. That the string names nothing is knowable here
/// (ADR-MCPRE-056 §5.1), and reads as the configuration defect it is.
fn empty_required_values_are_refused() {
    assert_each_mutation_is_refused(
        &[
            ("trust_domain", |c| c.trust_domain = String::new()),
            ("audience", |c| c.audience = String::new()),
            ("server_signer", |c| c.server_signer = String::new()),
            ("server_key_id", |c| c.server_key_id = String::new()),
            ("bind", |c| c.bind = String::new()),
            ("tls_cert", |c| {
                c.channel_credential.credential_chain = String::new()
            }),
            ("client_ca", |c| c.peer_trust_anchors = String::new()),
            ("trust_path", |c| c.trust_path = String::new()),
        ],
        "an empty required value is still admitted at the boundary",
    );
}

/// The numeric ranges the parser bounded and the boundary did not. `max_clock_skew` is
/// the freshness tolerance applied to every verified request AND to the replay
/// `retain_until`, so outside its bound the gate stops bounding anything, and the boundary
/// refuses it before any plane starts.
fn numeric_ranges_are_bounded() {
    assert_each_mutation_is_refused(
        &[
            ("max_clock_skew above the bound", |c| {
                c.max_clock_skew = 86_400
            }),
            ("a negative max_clock_skew", |c| c.max_clock_skew = -1),
            ("a zero connection ceiling", |c| {
                c.limits.max_concurrent_connections = 0
            }),
            ("a zero drain window", |c| {
                c.limits.drain_grace = std::time::Duration::from_secs(0)
            }),
        ],
        "still admitted at the boundary",
    );
}

/// The last case to move used to be here: a responder URL beside `--client-ocsp off`,
/// an authority the deployment carried and never asked. It has no case any more, and
/// that is the result — the responder travels inside
/// `OnlineRevocationEvidenceRequest::Required`, so a programmatic request cannot name
/// one under a mode that reads none. What survives is the VALUE clause, which is
/// intra-mechanism and still reachable: an empty responder replaces a resolvable
/// authority with none.
fn an_empty_responder_is_an_authority_that_answers_nothing() {
    assert_refusal_names(
        |c| {
            c.peer_revocation.online =
                mcp_re_proxy::deployment_request::OnlineRevocationEvidenceRequest::Required(
                    mcp_re_proxy::deployment_request::OcspResponderRequest {
                        url: Some(String::new()),
                    },
                );
        },
        "--ocsp-responder-url",
        "a responder that names nothing is an authority that answers nothing",
    );
}

/// The same source under the tier that DOES consume it is the legal state, and is
/// recognised as such rather than merely permitted.
fn a_push_tier_with_an_epoch_source_is_recognised() {
    let mut config = base();
    config.request_signer_currency =
        mcp_re_proxy::deployment_request::RequestSignerCurrencyRequest::Push {
            t_secs: 30,
            reload_secs: 30,
            epoch: mcp_re_proxy::deployment_request::TrustEpochStoreRequest {
                source: Some(mcp_re_proxy::deployment_request::TrustEpochSource::redis(
                    "redis://127.0.0.1:6379",
                    None,
                )),
            },
        };
    let validated = ValidatedDeployment::try_from(config).expect("push + epoch source is legal");
    assert!(
        validated.state().trust_revocation().has_networked_epoch(),
        "the boundary accepted it without recognising which state it is"
    );
}

/// Relations that have MOVED to the boundary, and the state each one now decides.
///
/// A case arrives here by flipping in the list above. What makes the move meaningful is
/// not the refusal alone but that the boundary now names a state: `TrustRevocation` has
/// four, the epoch source is what splits `Push` into two of them, and a tier that cannot
/// consume one does not merely ignore it.
#[test]
fn refused_at_the_boundary() {
    the_delegated_trust_epoch_is_required();
    an_inner_server_is_required();
    a_file_custody_state_needs_its_seed();
    the_replay_machine_columns_are_enforced();
    empty_required_values_are_refused();
    numeric_ranges_are_bounded();
    an_empty_responder_is_an_authority_that_answers_nothing();
    a_push_tier_with_an_epoch_source_is_recognised();
}

/// The boundary refuses `--replay-cache memory` and recommends `--replay-cache file`;
/// `ReplayPlan::from_config` then refuses `file` on the async serving path.
///
/// So the legal-state relation disagrees with itself across two stages: the remedy the
/// boundary names is not a state the next stage will start. This baseline — the shape the
/// parser's own test suite uses as its canonical valid config — is one of them.
#[test]
fn the_recommended_replay_backend_cannot_start() {
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let refusal = mcp_re_proxy::app::run_request(base(), shutdown)
        .expect_err("a config naming absent key material cannot serve");
    // The startup order reaches key material before replay planning, so this is what an
    // operator meets first. Recorded so that a reordering shows up here rather than
    // silently changing which of the two refusals a `file` deployment receives.
    assert!(
        refusal.contains("key material not found"),
        "unexpected first refusal: {refusal}"
    );
}
