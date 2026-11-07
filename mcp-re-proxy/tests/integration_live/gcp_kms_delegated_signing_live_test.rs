// SPDX-License-Identifier: Apache-2.0
//! Live GCP Cloud KMS — ADR-MCPRE-052 delegated-signing custody lane
//! (MCPRE-122 / #328).
//!
//! The sibling `gcp_kms_http_profile_live_test` proves Cloud KMS can sign an
//! RFC 9421 response DIRECTLY — one KMS `asymmetricSign` PER response, i.e. the
//! root key is on the hot path. This lane proves the ADR-MCPRE-052 posture that
//! removes it from the hot path: Cloud KMS is the root ISSUER that signs only a
//! short-lived compact-JWS **delegation credential** at issuance/rotation, while
//! an in-memory Ed25519 **delegated** key signs the per-request RFC 9421
//! responses. The load-bearing property proven here:
//!
//!   **Zero remote KMS operations on the per-request signing path** — signing N
//!   responses within one delegated key's life invokes Cloud KMS exactly once
//!   (the initial issuance), and `verify_delegated_response_full` accepts each
//!   response via the credential's attestation chain back to the KMS root.
//!
//! It wires `GcpKmsEd25519Backend` as the custody root issuer through the
//! wire-identical KMS seam `issue_delegation_credential_with_signer` (the same
//! seam the in-process reference issuer uses), so the KMS is a swap of the
//! injected issuer, not a code fork.
//!
//! Two entry points share one lane body:
//!   * `*_offline_local_seed` — NOT ignored: runs in the blocking feature-gated
//!     CI job via a local-key `KmsEd25519Backend` (no network),
//!     guarding the KMS-backend → custody-issuer wiring on every push.
//!   * `*_live` — `#[ignore]`: the real Cloud KMS backend; run from the cloud
//!     script / nightly lane with `-- --ignored` and `MCP_RE_GCP_*` set. FAILS
//!     LOUDLY if its configuration is absent — never a silent pass.
//!
//! Required environment for the live lane:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;

use crate::delegated_signing_lane::Lane;
use crate::local_seed_backend::offline_signer;

// The KMS root's `issuer_kid` (the identity anchor the verifier trusts). The
// delegated key ids the custody mints are `<ROOT_KID>/delegated/<n>`.
const ROOT_KID: &str = "gcp-kms-root-1";

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms delegated-signing lane: required env var {name} is not set — this lane must \
             run against a real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

/// The live Cloud KMS signer (root issuer), failing loudly if unconfigured.
fn live_signer() -> KmsResponseSigner {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCP_RE_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCP_RE_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        require_env("MCP_RE_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    KmsResponseSigner::new(Box::new(backend))
}

// ---- offline (hermetic, runs in blocking CI) ------------------------------

#[test]
fn gcp_kms_delegated_signing_offline_local_seed() {
    Lane::over_root(ROOT_KID).run(offline_signer());
}

// ---- live (real Cloud KMS; ignored) ---------------------------------------

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_delegated_signing_live() {
    Lane::over_root(ROOT_KID).run(live_signer());
}
