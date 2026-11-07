// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! Shared fixtures for the layer-A classifiers and the composition root: real-parser
//! `DeploymentRequest`s and the classified states projected from them.

use crate::cli;
use crate::deployment_request::DeploymentRequest;

/// A parsed `DeploymentRequest` for `source`, built through the REAL parser so the test
/// cannot drift from what the CLI actually produces. An empty `tls_key` is how the
/// parser represents delegated TLS, so it is passed through rather than defaulted.
///
/// SHARED because two owners need the same fixture and neither should carry a second
/// copy of it: the composition root's controls, and the key-file custody subtree's.
pub(crate) fn config_with(
    source: &str,
    seed: &str,
    tls_key: &str,
) -> crate::deployment_request::DeploymentRequest {
    let mut argv: Vec<&str> = BASE_ARGV.to_vec();
    argv.extend_from_slice(&["--key-source", source, "--trust-domain", "mcp.example.com"]);
    argv.extend_from_slice(key_source_flags(source));
    if !seed.is_empty() {
        argv.extend_from_slice(&["--signing-key-seed", seed]);
    }
    argv.extend_from_slice(&tls_key_flags(tls_key));
    let owned: Vec<String> = argv.into_iter().map(str::to_string).collect();
    crate::cli::parse_args(&owned)
        .unwrap_or_else(|e| panic!("{source:?} config must parse: {e}"))
        .config()
        .clone()
}

/// The flags every `config_with` request shares, before the key source is named.
const BASE_ARGV: [&str; 26] = [
    "--bind",
    "127.0.0.1:8443",
    "--audience",
    "did:web:server-1.mcp.example.com",
    "--server-signer",
    "did:web:server-1.mcp.example.com",
    "--server-key-id",
    "server-key-1",
    "--tls-cert",
    "/cert",
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
    "--replay-redis-url",
    "redis://127.0.0.1:6379",
    "--replay-durability-tier",
    "redis-wait-quorum:1:100",
];

/// The flags that make `source` a complete `--key-source` request.
fn key_source_flags(source: &str) -> &'static [&'static str] {
    match source {
        "file" => &[],
        "pkcs11" => &[
            "--pkcs11-module",
            "/m.so",
            "--pkcs11-token-label",
            "t",
            "--pkcs11-key-label",
            "k",
            "--pkcs11-pin-file",
            "/etc/mcp-re/pin",
        ],
        "aws-kms" => &[
            "--aws-kms-region",
            "us-east-1",
            "--aws-kms-key-id",
            "alias/k",
        ],
        "gcp-kms" => &[
            "--gcp-kms-key-version",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ],
        other => panic!("no fixture for --key-source {other}"),
    }
}

/// The TLS-key flags. An empty `tls_key` means delegated TLS; the parser only leaves it
/// empty when a delegated TLS custody is configured, so express that rather than omitting
/// it.
fn tls_key_flags(tls_key: &str) -> Vec<&str> {
    if tls_key.is_empty() {
        return vec![
            "--gcp-kms-tls-key-version",
            "projects/p/locations/l/keyRings/r/cryptoKeys/tls/cryptoKeyVersions/1",
        ];
    }
    vec!["--tls-key", tls_key]
}

/// The two custody states the disk projection is a function of.
///
/// Classified rather than hand-built, so these tests measure what the validation
/// boundary actually recognises for the fixture above.
pub(crate) fn custody_states(
    config: &crate::deployment_request::DeploymentRequest,
) -> (
    crate::config_state::CustodyState,
    crate::config_state::ChannelCredentialCustodyState,
) {
    let (custody, violations) = crate::config_state::custody::classify_and_validate(config);
    assert!(violations.is_empty(), "fixture refused: {violations:?}");
    let (channel_credential_custody, violations) =
        crate::config_state::channel_credential_custody::classify_and_validate(config);
    assert!(violations.is_empty(), "fixture refused: {violations:?}");
    (
        custody.expect("the fixture names a custody state"),
        channel_credential_custody.expect("the fixture names a TLS custody state"),
    )
}

/// The same configuration with the linearizable replay state requested.
///
/// Built by mutating the accepted request and re-classifying, because the replay state
/// is only obtainable from its own validator — which is what makes possessing one mean
/// its locators were checked.
pub(crate) fn legal_linearizable_config() -> DeploymentRequest {
    let mut config = legal_config();
    config.replay.store = None;
    config.replay.durability = Some(crate::replay_tier::ReplayDurabilityTier::Linearizable);
    config.replay.store = Some(crate::deployment_request::ReplayStoreRequest::etcd(
        "http://127.0.0.1:2379",
    ));
    config
}

/// The replay plan a linearizable deployment produces.
///
/// Projected from a classified state rather than built as a literal, so a test holds
/// only plans a configuration could actually reach. The literals these replaced could
/// name a store paired with any tier at all, including tiers `classify` refuses.
pub(crate) fn linearizable_replay_plan() -> super::replay::ReplayPlan {
    super::replay::classify_and_validate(&legal_linearizable_config())
        .0
        .expect("the linearizable fixture names a CP store endpoint")
        .materialization_plan()
}

/// The replay plan a quorum-Redis deployment produces.
pub(crate) fn redis_replay_plan() -> super::replay::ReplayPlan {
    super::replay::classify_and_validate(&legal_config())
        .0
        .expect("the accepted fixture names a redis replay store")
        .materialization_plan()
}

/// The same configuration with a shared continuation store requested.
pub(crate) fn shared_continuation_config() -> DeploymentRequest {
    let mut config = legal_config();
    config.continuation_control.shared = Some(
        crate::deployment_request::SharedStoreRequest::redis("redis://127.0.0.1:6379"),
    );
    config
}

/// The same configuration with admission enforced under a named authority.
pub(crate) fn enforcing_admission_config() -> DeploymentRequest {
    let mut config = legal_config();
    config.admission = crate::deployment_request::AdmissionRequest::Required(
        crate::deployment_request::AdmissionGateRequest {
            authority_kid: "authority-1".to_string(),
            authority_pubkey_b64url: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
                .public_key()
                .to_b64url(),
            store: crate::deployment_request::SharedStoreRequest::redis("redis://127.0.0.1:6379"),
            availability: crate::deployment_request::AdmissionAvailabilityRequest::FailClosed,
            record_max_age_secs: std::num::NonZeroU64::new(60).expect("nonzero"),
        },
    );
    config
}

/// The same configuration declaring a served MCP protocol version.
pub(crate) fn versioned_transport_config() -> DeploymentRequest {
    let mut config = legal_config();
    config.mcp_protocol_versions = vec!["2026-07-28".to_string()];
    config
}

/// The retention state a deployment configured with this directory reaches.
pub(crate) fn retention_at(directory: String) -> super::RetentionState {
    let mut config = legal_config();
    config.retained_evidence_dir = Some(directory);
    super::evidence::classify(&config).0
}

/// The posture a published tier plus its material names.
///
/// The tier vocabulary is what a test is written in; the union is what the request
/// holds. In production the CLI adapter performs this mapping, and this is its fixture
/// twin — so a fixture cannot state an epoch source under a tier that reads none.
fn currency_posture(
    tier: crate::revocation_tier::RevocationTier,
    reload_secs: Option<u64>,
    epoch: Option<(&str, &str)>,
) -> crate::deployment_request::RequestSignerCurrencyRequest {
    use crate::deployment_request::RequestSignerCurrencyRequest as Currency;
    let source = epoch.map(|(url, key)| {
        crate::deployment_request::TrustEpochSource::redis(url, Some(key.to_string()))
    });
    match tier {
        crate::revocation_tier::RevocationTier::BoundedCache { t_secs } => Currency::BoundedCache {
            t_secs,
            reload_secs,
        },
        crate::revocation_tier::RevocationTier::Live => Currency::Live {
            reload_secs: reload_secs.unwrap_or_default(),
        },
        crate::revocation_tier::RevocationTier::Push { t_secs } => Currency::Push {
            t_secs,
            reload_secs: reload_secs.unwrap_or_default(),
            epoch: crate::deployment_request::TrustEpochStoreRequest { source },
        },
    }
}

/// The trust-revocation state a deployment with these settings reaches.
///
/// Built through the classifier, so a test names a posture a configuration could
/// actually request rather than assembling one from parts.
pub(crate) fn revocation_posture(
    tier: crate::revocation_tier::RevocationTier,
    reload_secs: Option<u64>,
    epoch: Option<(&str, &str)>,
) -> super::TrustRevocationState {
    let mut config = legal_config();
    config.request_signer_currency = currency_posture(tier, reload_secs, epoch);
    super::trust_revocation::classify_and_validate(&config)
        .0
        .expect("the requested revocation posture is legal")
}

/// The credential window a deployment with this lifetime and connection age reaches.
///
/// Through the classifier, so a test cannot hold a window whose connection age outlives
/// its certificate — which is the pairing the owner exists to make unconstructible.
pub(crate) fn credential_window(
    cert_lifetime_secs: u64,
    connection_age_secs: u64,
) -> super::ClientCredentialWindow {
    let mut config = legal_config();
    config.max_client_cert_lifetime = Some(std::time::Duration::from_secs(cert_lifetime_secs));
    config.limits.max_connection_age = Some(std::time::Duration::from_secs(connection_age_secs));
    super::client_credential_window::classify_and_validate(&config)
        .0
        .expect("the fixture names a legal credential window")
}

/// The trust plan a deployment in this posture projects.
///
/// Through the boundary and then through `response_authority_plans`, so the plan's
/// revocation posture, its derived reload cadence, its document and its response
/// authority all come from ONE accepted deployment. The literal this replaced could pair
/// any state with any cadence, and did: it named a 30s reload beside a state carrying 5s.
pub(crate) fn trust_plan(
    tier: crate::revocation_tier::RevocationTier,
    reload_secs: Option<u64>,
    epoch: Option<(&str, &str)>,
) -> crate::startup_plan::TrustPlan {
    let mut config = legal_config();
    config.request_signer_currency = currency_posture(tier, reload_secs, epoch);
    let validated = super::validation::ValidatedDeployment::try_from(config)
        .expect("the requested trust posture is a legal deployment");
    crate::startup_plan::response_authority_plans(&validated).0
}

/// The CRL state a deployment with these files and cadence reaches.
/// The freshness window a deployment with this skew resolves.
///
/// Through the classifier, so a test cannot hold a window outside the §5.1 bound.
pub(crate) fn freshness(max_clock_skew: i64) -> super::FreshnessWindow {
    let mut config = legal_config();
    config.max_clock_skew = max_clock_skew;
    super::freshness::classify_and_validate(&config)
        .0
        .expect("the fixture skew is within the bound")
}

pub(crate) fn crl_posture(paths: &[&str], cadence_secs: Option<u64>) -> super::CrlRevocationState {
    let mut config = legal_config();
    config.peer_revocation.lists.paths = paths.iter().map(|p| p.to_string()).collect();
    config.peer_revocation.lists.reload_secs = cadence_secs;
    super::crl_revocation::classify_and_validate_crl(&config)
        .0
        .expect("the fixture CRL posture is legal")
}

/// The client-revocation plan such a deployment projects.
pub(crate) fn crl_plan(
    paths: &[&str],
    cadence_secs: Option<u64>,
) -> super::crl_revocation::ClientRevocationPlan {
    crl_posture(paths, cadence_secs).client_revocation_plan()
}

/// The TLS-custody state a deployment delegating the handshake key to a PKCS#11 token
/// reaches.
pub(crate) fn channel_custody_delegated_pkcs11(
    key_label: &str,
) -> super::ChannelCredentialCustodyState {
    let mut config = legal_config();
    config.channel_credential.key = crate::deployment_request::ChannelKeyRequest::Delegated(
        crate::deployment_request::DelegatedChannelKeyRequest::Pkcs11(
            crate::deployment_request::Pkcs11ChannelKeyRequest {
                key_label: key_label.to_string(),
            },
        ),
    );
    super::channel_credential_custody::classify_and_validate(&config)
        .0
        .expect("a delegated PKCS#11 TLS key names a state")
}

/// The custody state a deployment holding the signing key on a PKCS#11 token reaches.
pub(crate) fn custody_pkcs11() -> super::CustodyState {
    let mut config = legal_config();
    config.response_signing.source = crate::deployment_request::SigningSourceRequest::Pkcs11(
        crate::deployment_request::Pkcs11SigningSourceRequest {
            module: Some("/lib/softhsm.so".to_string()),
            pin_file: Some("/pin".to_string()),
            token_label: Some("token".to_string()),
            key_label: Some("signing".to_string()),
        },
    );
    super::custody::classify_and_validate(&config)
        .0
        .expect("a complete PKCS#11 custody configuration names a state")
}

/// A configuration the parser accepts, for a machine's tests to mutate.
///
/// From `parse_args` rather than a struct literal so that a test which expects a
/// refusal is measuring the mutation it made, not a defect it inherited.
pub(crate) fn legal_config() -> DeploymentRequest {
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
        .expect("the baseline parses")
        .config()
        .clone()
}
