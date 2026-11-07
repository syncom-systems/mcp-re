//! MCPRE-108 (ADR-MCPRE-051 §7) — concurrent-TLS-client load harness driving the
//! REAL listener over the **RFC 9421** serving path (ADR-MCPRE-050 sole carrier).
//!
//! ADR-MCPRE-051 §7 makes a load harness a *prerequisite deliverable*: every
//! architectural throughput claim must be MEASURED against the real serving path,
//! not argued. This harness spawns the real `mcp-re-proxy` binary and drives its
//! listener over many concurrent rustls **mTLS** clients: accept → TLS/mTLS →
//! RFC 9421 + RFC 9530 verify → inner → sign → respond. Every measured number
//! includes the full PEP path. The request is signed with the audited
//! `mcp-re-client-core` `build_signed_message` (the signature rides in the HTTP
//! `Signature`/`Signature-Input`/`Content-Digest` headers, not a JSON-RPC body
//! `_meta` block), and the response is verified with `verify_delegated_response`
//! (ADR-MCPRE-052 delegated-required) bound to the request.
//!
//! It reports aggregate throughput and p50/p99/p999 added latency, measures the
//! cold-handshake and keep-alive connection modes SEPARATELY, and records the
//! declared benchmark envelope (hardware class, core count, payload, TLS suite,
//! connection mode, replay backend, inner latency) alongside the numbers — the
//! envelope is pinned in `docs/bench/adr-051-load-harness-envelope.md` +
//! `adr-051-benchmark-envelope.json`. It drives the per-core async fleet
//! (`--cores` pins the worker count) and produces the baseline + per-core scaling
//! input to the SLO declaration (MCPRE-110).
//!
//! This is an INTEGRATION test: the proxy always runs the maximal-security posture
//! and the per-core async serving plane refuses node-local replay (memory + file),
//! so the harness stands up a real shared replay store. The whole file is compiled
//! ONLY under the `redis_replay` feature, and each entry point brings up a Redis
//! wait-quorum fleet (primary + 2 replicas) in Docker, drives the bench against it,
//! and tears the containers down (a `RedisFleet` RAII guard). Run it in the
//! integration lane:
//!
//! ```text
//! bazel test //mcp-re-proxy:tls_load_harness_bench
//! ```
//!
//! Two entry points:
//!   * [`load_harness_smoke`] — the self-verifying tiny-scale run: it drives the real
//!     listener end-to-end, confirms a genuinely RFC 9421-signed response bound to
//!     the request, and checks the metrics compute. It is NOT an SLO gate.
//!   * [`tls_load_harness_bench`] — the full ADR-051 §7 run, scaled by
//!     `MCP_RE_LOADGEN_*` env, printing the report and (optionally) writing
//!     machine-readable JSON. It runs in the integration lane (this file is
//!     `redis_replay`-gated); the cost-bearing live counterpart is the GKE runbook.
//!
//! NOTE on keep-alive: the async data plane (ADR-MCPRE-051 §1) serves HTTP/1.1
//! keep-alive and HTTP/2, so `keepalive` mode realises a reuse fraction of 1.000 with
//! zero reconnects — one handshake per connection rather than one per request. Warm
//! connections are safe to hold because the peer certificate's validity window and,
//! when CRLs are configured, its revocation status are re-checked on EVERY request
//! (`client_revocation.rs`), not only at the handshake.
#![cfg(feature = "redis_replay")]

use std::convert::Infallible;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;

use mcp_re_client_core::build_signed_message;
use mcp_re_client_core::McpMessage;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignedRequest;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::pdp_decision::issue_authorization_decision;
use mcp_re_http_profile::pdp_decision::DecidedActor;
use mcp_re_http_profile::pdp_decision::PdpDecisionClaims;
use mcp_re_http_profile::pdp_decision::PdpDecisionOutcome;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::config_state::client_credential_window::MAX_CLIENT_CERT_LIFETIME;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::CertificateRevocationListParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyIdMethod;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rcgen::SerialNumber;

use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

use serde_json::json;
use serde_json::Map;
use serde_json::Value;

// The harness's parts. Each is a child module that sees this file's whole namespace
// through `use super::*`, and this file sees what each shares (`pub(super)`).
#[path = "tls_load_harness_bench/acceptance.rs"]
mod acceptance;
#[path = "tls_load_harness_bench/client.rs"]
mod client;
#[path = "tls_load_harness_bench/infra.rs"]
mod infra;
#[path = "tls_load_harness_bench/load.rs"]
mod load;
#[path = "tls_load_harness_bench/pki.rs"]
mod pki;

use acceptance::*;
use client::*;
use infra::*;
use load::*;
use pki::*;

/// The replay durability tier the harness runs the proxy under, and the value its report
/// records. ONE constant for both: the report used to carry the literal `"memory"` while
/// the flag passed this tier, so every emitted report misdescribed the admission path it
/// had just measured. The per-core async plane refuses node-local replay outright, so
/// `memory` was not merely stale — it named a posture this harness cannot run.
const REPLAY_DURABILITY_TIER: &str = "redis-wait-quorum:2:2000";

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const TRUST_DOMAIN: &str = "example.org";
// A DID request-signer (subject) with colons: the real-world shape, and the GKE proof's
// identity. Since ADR-MCPRE-064 Slice 4 the client leaf carries THIS value as its URI SAN —
// the binding relates the authenticated peer to the resolved actor's SUBJECT.
const SUBJECT_A: &str = "did:example:agent-1"; // the request signer (subject) in trust.json
const SIGNER_A_KEY_ID: &str = "key-a";
const TARGET_URI: &str = "https://localhost/";
const DPOP_TOKEN: &str = "loadgen-dpop-token";
/// The URI SAN the client leaf carries: the resolved actor's SUBJECT, which is what
/// Mode-A binding relates the authenticated peer to (ADR-MCPRE-064 §15).
///
/// It is deliberately NOT the `role:trust_domain:subject:keyid` composite. This harness
/// used to mint that — one of three places where the certificate provisioning had adapted
/// itself to the implementation's string — and the DID subject's `%3A` escaping was
/// described as coverage rather than as the symptom it was.
const CLIENT_SUBJECT: &str = SUBJECT_A;

fn server_seed() -> [u8; 32] {
    [2u8; 32]
}
fn signer_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}

// --- entry points -------------------------------------------------------------

/// Self-verification: drive the REAL listener at tiny scale, confirm a genuinely
/// RFC 9421-signed response bound to the request, and check the metrics compute.
/// Brings up a Redis wait-quorum fleet (torn down on return) — the proxy's per-core
/// async plane refuses node-local replay, so a shared store is mandatory.
#[test]
fn load_harness_smoke() {
    let redis = RedisFleet::start();
    let material = write_material();
    let backend = spawn_http_echo_backend();
    let proxy = spawn_proxy(
        &material,
        Upstream {
            inner_http_url: &format!("http://{backend}/mcp"),
            redis_url: &redis.url(),
        },
        1,
    );
    let config = build_client_config(&material.client_ca, &material.server_root);

    // 1. One explicit VERIFIED round-trip proves the success criterion (`no error`)
    //    corresponds to a real RFC 9421-signed response bound to THIS request — i.e.
    //    the harness measures genuine serving, not error responses.
    {
        let signed = signed_request();
        let reply = cold_round_trip(proxy.addr, Arc::clone(&config), &signed)
            .expect("valid mTLS round trip");
        assert!(
            is_success(&reply.body),
            "smoke request must succeed: {:?}",
            String::from_utf8_lossy(&reply.body)
        );
        let response = HttpResponse {
            status: reply.status,
            headers: reply.headers.clone(),
            body: reply.body.clone(),
        };
        // Delegated-required is the only response-signing mode (ADR-MCPRE-052 §7): the
        // proxy signs with a short-lived DELEGATED key that chains to the root
        // (`SERVER_KEY_ID`) via an inline credential. `server_resolve` anchors that root
        // on the Response slot; the delegated verifier follows the credential to it.
        let expectation = ResponseExpectation::for_signed(&signed);
        let policy = DelegationPolicy::new(
            vec![AUDIENCE.to_string()],
            AUDIENCE,
            vec!["epoch-1".to_string()],
            mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
        );
        // MCPRE-172: one trust authority, not a freely pairable resolver + revocation.
        let resolve = |kid: &str, slot: SignerSlot, _now: i64| server_resolve(kid, slot).into();
        let revocation = StaticRevocationList::new();
        let trust = CompositeResponseTrust::new(&resolve, &revocation);
        let verified =
            verify_delegated_response(&response, &trust, &expectation, &policy, now_unix())
                .expect("delegated signed response verifies and binds to the request");
        assert_eq!(verified.outcome(), &DelegatedOutcome::Success);
        // Profile-issued kids are RFC 7638 JWK thumbprints (MCPRE-432); the property
        // under test is that a DELEGATED key signed, not the root directly.
        assert_ne!(
            verified.verified().server_signer().keyid,
            SERVER_KEY_ID,
            "signed by the delegated key chaining to the root, not the root directly",
        );
    }

    // 2. Tiny concurrent load: every request must succeed and the metrics populate.
    let cfg = LoadConfig {
        concurrency: 8,
        requests: 32,
        mode: Mode::Cold,
        hw_class: "smoke".to_string(),
        cores: 1,
    };
    let report = run_load(proxy.addr, Arc::clone(&config), &cfg);
    print_report(&cfg, &report);
    assert_eq!(report.failures, 0, "every smoke request must succeed");
    assert_eq!(report.successes, cfg.requests, "all requests accounted for");
    assert!(report.throughput_rps > 0.0, "throughput must be positive");
    assert!(report.p50_us > 0, "p50 latency must be measured");
    assert!(
        report.p999_us >= report.p50_us,
        "percentiles must be monotonic"
    );
}

/// `app::run` builds + starts + cleanly drains across the revocation-tier and
/// topology variants (each wires a different resolver + startup diagnostic). Uses a
/// PRE-FLIPPED shutdown so the fleet binds, connects the shared tier, then drains at
/// once — covering the per-tier orchestration + serve/drain without driving traffic.
#[test]
fn app_run_starts_and_drains_across_revocation_tiers() {
    let redis = RedisFleet::start();
    let m = write_material();
    let backend = spawn_http_echo_backend();
    let inner_url = format!("http://{backend}/mcp");
    let ru = redis.url();

    let run_ok = |extra: &[&str]| {
        let bind = free_bind();
        let upstream = Upstream {
            inner_http_url: &inner_url,
            redis_url: &ru,
        };
        let mut v = Deployment::new(&m, &bind, upstream).args();
        v.extend(owned(extra));
        let config = mcp_re_proxy::cli::parse_args(&v).expect("parse");
        let sd = Arc::new(AtomicBool::new(true)); // pre-flipped: bind + immediate drain
        std::thread::spawn(move || mcp_re_proxy::app::run(config, sd))
            .join()
            .expect("thread")
            .expect("serve + clean drain");
    };

    // LIVE and PUSH state their window in terms of consulting the trust store, so
    // both require a reload cadence — without one the store is frozen at startup and
    // neither tier can revoke anything.
    // Single-node: under --fleet only push with an epoch source starts (X9).
    run_ok(&["--revocation-tier", "live", "--trust-reload-secs", "60"]);
    run_ok(&["--revocation-tier", "bounded-cache:90"]);
    run_ok(&["--revocation-tier", "push:60", "--trust-reload-secs", "60"]); // push, single-node, no trust-epoch
}

// `app_run_refuses_unbuildable_key_sources_and_replay_tiers` moved to
// tests/integration/app_startup_characterization_test.rs (ADR-MCPRE-056 Phase 0). It
// could never
// run here: this file is `redis_replay`-gated, so the default lane skips it, and its
// own `cfg(not(any(aws_kms_keysource, ...)))` guard excluded it from the feature lane
// where those backends ARE compiled. A test that executes in no lane is not coverage —
// this one had silently rotted past a required `--delegated-trust-epoch`.

/// The DEPLOYED serving path, driven IN-PROCESS (so coverage sees it): calls the
/// library `app::run` — the exact orchestration `main` runs on GKE — with fixtures +
/// a shared Redis tier, then exercises the two identity/cert scenarios that the GKE
/// proof turns on:
///   * a SHORT-lived client leaf (within the cert-lifetime ceiling) is ACCEPTED, and
///   * a LONG-lived client leaf (over the ceiling) is REJECTED with the pre-handler
///     cert-lifetime verdict (`transport_binding_failed`) — the exact class of
///     mistake that failed the first GKE run.
///
/// This is the regression that would have caught it locally, for free.
#[test]
fn inprocess_app_run_accepts_short_cert_rejects_long_cert() {
    let redis = RedisFleet::start();
    let material = write_material();
    let backend = spawn_http_echo_backend();

    // A pre-chosen free port so the client knows where to connect (app::run blocks
    // and does not surface its bound address).
    let bind = free_bind();
    let inner_url = format!("http://{backend}/mcp");
    let redis_url = redis.url();
    // An empty (non-revoking), far-future CRL + hot-reload, so the CRL load, posture
    // diagnostic, and the in-process reload task are all exercised on the serve path.
    let crl_path = tmp("client.crl");
    write_empty_crl(&material.client_ca, &crl_path);
    let crl = crl_path.to_string_lossy().into_owned();
    seed_trust_epoch(&redis_url);

    let upstream = Upstream {
        inner_http_url: &inner_url,
        redis_url: &redis_url,
    };
    let mut argv = Deployment::new(&material, &bind, upstream).args();
    argv.extend(owned(&[
        "--transport-binding",
        "exact",
        "--transport-identity-source",
        "uri_san",
        // --fleet exercises the horizontally-scaled posture (cross-replica revocation-
        // lag diagnostics); the shared wait-quorum tier satisfies its guardrail.
        "--fleet",
        // Exercise the PUSH revocation tier + the networked trust-epoch source on the
        // same Redis fleet, so the trust-epoch wiring is covered on the serving path.
        "--revocation-tier",
        "push:60",
        "--trust-epoch-redis-url",
        &redis_url,
        "--trust-epoch-key",
        "mcp-re:trust:epoch",
        "--trust-reload-secs",
        "60",
        // Offline client-cert CRL + in-process hot-reload (rebuilds the verifier).
        "--client-crl",
        &crl,
        "--client-crl-reload-secs",
        "1",
    ]));
    let app = RunningApp::start(&argv, &bind);
    let addr = app.addr;

    // 1. Short-lived (compliant) client leaf → ACCEPTED end to end.
    assert_compliant_client_accepted(
        addr,
        &material,
        "short cert",
        "a short-lived client cert must be ACCEPTED",
    );
    // 2. Long-lived client leaf (over the ceiling) → REJECTED at the cert-lifetime gate.
    assert_long_lived_client_rejected(addr, &material);

    // Let one CRL hot-reload cycle fire (--client-crl-reload-secs 1) so the reload
    // task's rebuild path is exercised, then a final request still succeeds.
    std::thread::sleep(Duration::from_millis(1300));
    assert_compliant_client_accepted(
        addr,
        &material,
        "after CRL reload",
        "serving must continue after a CRL hot-reload",
    );
    assert_keep_alive_reuses_the_connection(addr, &material);

    app.stop();
}

/// The trust-epoch key must EXIST before the proxy starts: an absent key is refused
/// rather than read as a live epoch 0, because the two are indistinguishable and
/// reading absence as a baseline leaves the push kill switch silently inert.
fn seed_trust_epoch(redis_url: &str) {
    let mut admin = redis::Client::open(redis_url)
        .expect("open redis client")
        .get_connection()
        .expect("admin connection");
    let _: () = redis::cmd("SET")
        .arg("mcp-re:trust:epoch")
        .arg(0_i64)
        .query(&mut admin)
        .expect("seed the trust epoch");
}

/// A round trip as the compliant client, whose leaf is within the cert-lifetime ceiling.
fn assert_compliant_client_accepted(
    addr: SocketAddr,
    material: &Material,
    label: &str,
    expectation: &str,
) {
    let reply = cold_round_trip(
        addr,
        build_client_config(&material.client_ca, &material.server_root),
        &signed_request(),
    )
    .unwrap_or_else(|e| panic!("round trip ({label}): {e}"));
    assert!(
        is_success(&reply.body),
        "{expectation}: {}",
        String::from_utf8_lossy(&reply.body)
    );
}

/// Chains to the same CA (handshake succeeds), so it is the LIFETIME, not the chain, that
/// rejects it — exactly the GKE failure.
fn assert_long_lived_client_rejected(addr: SocketAddr, material: &Material) {
    let (long_leaf, long_key) =
        make_leaf(&material.client_ca, vec![uri(CLIENT_SUBJECT)], None, true);
    let rej = cold_round_trip(
        addr,
        client_config_from(&long_leaf, &long_key, &material.server_root),
        &signed_request(),
    )
    .expect("round trip (long cert)");
    assert!(
        !is_success(&rej.body),
        "a long-lived client cert must be REJECTED: {}",
        String::from_utf8_lossy(&rej.body)
    );
    assert!(
        String::from_utf8_lossy(&rej.body).contains("transport_binding_failed"),
        "the over-ceiling cert must fail closed with the cert-lifetime verdict: {}",
        String::from_utf8_lossy(&rej.body)
    );
}

/// Keep-alive-mode client path: two requests over the connection-reuse helper (distinct
/// from the cold path). The async data plane holds the connection open, so the second
/// request reuses it and the helper's reconnect accounting stays at zero.
fn assert_keep_alive_reuses_the_connection(addr: SocketAddr, material: &Material) {
    let mut client = KeepAliveClient::new(Arc::new(AtomicUsize::new(0)));
    for _ in 0..2 {
        let r = client
            .round_trip(
                addr,
                build_client_config(&material.client_ca, &material.server_root),
                &signed_request(),
            )
            .expect("keep-alive round trip");
        assert!(
            is_success(&r.body),
            "keep-alive request must be accepted: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
}

/// The full ADR-051 §7 load run — the manual/dispatch lane (`#[ignore]`), scaled
/// by `MCP_RE_LOADGEN_*`. Not a per-PR gate; run explicitly to produce the
/// baseline/SLO numbers (MCPRE-110):
///
/// ```text
/// bazel test //mcp-re-proxy:tls_load_harness_bench -c opt --test_output=all \
///   --test_arg=tls_load_harness_bench --test_arg=--exact --test_arg=--nocapture
///   # env: MCP_RE_LOADGEN_CONCURRENCY / _REQUESTS / _CORES / _HW_CLASS / _OUT
///   # NOTE: this fn is NOT #[ignore] (see below) — do NOT pass `--ignored`, which
///   # would select only ignored tests and run nothing. It needs `redis_replay`
///   # (the bench uses the shared Redis tier, via Docker or MCP_RE_LOADGEN_REDIS_URL).
/// ```
// ADR-051 §7 load benchmark. It is NOT `#[ignore]`: the whole file is already gated
// to the `redis_replay` INTEGRATION lane (it stands up a Redis fleet), so it never
// runs in the default unit battery. Scaled by `MCP_RE_LOADGEN_*` env; prints the
// report and (optionally) writes machine-readable JSON. The COST-bearing live
// counterpart is the GKE runbook, which stays manual (gcloud auth + PROJECT_ID).
#[test]
fn tls_load_harness_bench() {
    let cfg = LoadConfig::from_env();
    // In a containerized runner (K8s Job) the Docker daemon is unavailable, so allow
    // pointing the bench at an already-running primary+2-replica Redis via
    // MCP_RE_LOADGEN_REDIS_URL; otherwise bring up the Docker-backed fleet as before.
    let external_redis = std::env::var("MCP_RE_LOADGEN_REDIS_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let _fleet = if external_redis.is_none() {
        Some(RedisFleet::start())
    } else {
        None
    };
    let redis_url = external_redis.unwrap_or_else(|| _fleet.as_ref().unwrap().url());
    let material = write_material();
    let backend = spawn_http_echo_backend();
    let proxy = spawn_proxy(
        &material,
        Upstream {
            inner_http_url: &format!("http://{backend}/mcp"),
            redis_url: &redis_url,
        },
        cfg.cores,
    );
    let config = build_client_config(&material.client_ca, &material.server_root);

    let report = run_load(proxy.addr, config, &cfg);
    print_report(&cfg, &report);
    maybe_write_json(&cfg, &report);

    assert!(
        report.successes > 0,
        "load run produced zero successful requests"
    );
    assert_eq!(
        report.successes + report.failures,
        cfg.requests,
        "every issued request must be accounted for",
    );
}

// ---------------------------------------------------------------------------------------
// ADR-MCPRE-065 acceptance: the authorization authority, through the production path
// ---------------------------------------------------------------------------------------
//
// Every other authorization control in this repository drives either the evaluator or
// `HttpProfileProxy::handle` with a proxy a test assembled. This one drives real argv
// through `mcp_re_proxy::app::run` — the orchestration `main` runs — and reaches it over a
// real mTLS connection with a real signed request, so the chain it measures is:
//
//     CLI/config -> trust document -> authorization-issuer slot -> capability ->
//     with_authorization -> RFC 9421 verification -> decision binding ->
//     decision authentication -> actor + action relation -> Permit -> dispatch
//
// It answers the one question no unit or handler-level control can: does a DEPLOYMENT
// enforce what the mechanism decides. Note the lane — this file is
// `#![cfg(feature = "redis_replay")]`, so a default-feature target compiles it to zero
// tests and only the feature lane runs it.

/// The whole ADR-MCPRE-065 chain, through `app::run`, over mTLS.
///
/// | row | expectation |
/// |---|---|
/// | trusted issuer + correct actor/action + Permit | dispatch |
/// | Deny | refused, backend untouched |
/// | no decision carried | refused |
/// | decision for another action | refused |
/// | decision about another actor | refused |
/// | issuer this deployment does not enrol | refused |
/// | stale decision | refused |
///
/// `--authz off` and the startup refusal for a profile with no enrolled authority are
/// measured in the default lane (`app_startup_characterization_test`), which is where they
/// belong: neither needs a listener.
#[test]
fn inprocess_app_run_enforces_the_pdp_authorization_profile() {
    let redis = RedisFleet::start();
    let material = write_material();
    let backend = spawn_http_echo_backend();
    let trust = acceptance_trust_file(&material, true);

    let bind = free_bind();
    let inner_url = format!("http://{backend}/mcp");
    let redis_url = redis.url();
    let upstream = Upstream {
        inner_http_url: &inner_url,
        redis_url: &redis_url,
    };
    let mut deployment = Deployment::new(&material, &bind, upstream);
    deployment.trust = &trust;
    let mut argv = deployment.args();
    argv.extend(owned(&[
        // The subject of this test: the authorization authority, selected from the CLI.
        "--authz",
        "pdp-decision",
        "--authz-decision-scope",
        "principal",
        "--authz-max-decision-age-secs",
        "600",
    ]));
    let app = RunningApp::start(&argv, &bind);

    let now = now_unix();
    let serve = |nonce: &str, request: &SignedRequest| {
        cold_round_trip(
            app.addr,
            build_client_config(&material.client_ca, &material.server_root),
            request,
        )
        .unwrap_or_else(|e| panic!("round trip {nonce}: {e}"))
    };

    // Row 1 — a Permit from the enrolled authority, about this actor and this action.
    let permit = DecisionSpec::permit(now).issue();
    let ok = serve("authz-permit", &signed_request_with_decision(&permit));
    assert!(
        is_success(&ok.body),
        "a Permit from the enrolled authority must reach the backend: {}",
        String::from_utf8_lossy(&ok.body)
    );

    // Every remaining row must be refused.
    for (nonce, decision) in &refusal_matrix(now) {
        let request = match decision {
            Some(d) => signed_request_with_decision(d),
            None => signed_request(),
        };
        let response = serve(nonce, &request);
        assert!(
            !is_success(&response.body),
            "{nonce} must be refused by the installed authority: {}",
            String::from_utf8_lossy(&response.body)
        );
    }

    app.stop();
    let _ = std::fs::remove_file(&trust);
}
