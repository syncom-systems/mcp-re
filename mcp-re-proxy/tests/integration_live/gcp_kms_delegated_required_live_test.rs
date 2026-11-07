// SPDX-License-Identifier: Apache-2.0
//! Live GCP Cloud KMS — ADR-MCPRE-052 delegated-REQUIRED serving + authority-flip
//! lanes (MCPRE-122 / #328). The local pre-GKE gate for running the delegated path
//! on a REAL Cloud KMS root.
//!
//! The sibling `gcp_kms_delegated_signing_live_test` proves the custody state
//! machine with a KMS root (issuance/rotation/verify, zero per-request KMS ops).
//! THIS lane goes two steps further, on the same KMS key:
//!
//!   * **Serving** — drives the PRODUCTION wiring `build_delegated_signing(config,
//!     kms_root)` + `HttpProfileProxy::new_delegated` — the exact path `app::run`
//!     takes for delegated-signing (the only response mode) — and serves real
//!     requests through the PEP. The KMS root is wrapped in a counting
//!     `ResponseSigner` so the load-bearing property is asserted at the SERVING
//!     altitude: N served responses invoke Cloud KMS ZERO extra times (one op per
//!     key issuance/rotation, none per request). Also proves bound rejection,
//!     rotation to a successor, and the client revocation seam (allow + deny) on a
//!     KMS-rooted credential.
//!
//!   * **Authority flip** — on ONE KMS key, demonstrates the response-signing
//!     authority cutover is a real security boundary, not cosmetic:
//!       1. the PRE-052 authority (the KMS signs the response DIRECTLY, with no
//!          delegation evidence block) is REJECTED by a delegated-required verifier
//!          (fails closed) — no downgrade to the old response authority;
//!       2. the POST-052 authority (the KMS ISSUES a credential; an in-memory
//!          delegated key signs) is ACCEPTED;
//!       3. a TRUST-EPOCH flip: a KMS-rooted credential minted under the old epoch
//!          is rejected once the accepted-epoch set advances
//!          (`delegation_trust_epoch_stale`), and accepted under a bounded-rollout
//!          `{new, old}` window;
//!       4. a KEY-authority rotation + revocation flip: after the KMS issues a
//!          successor, revoking the predecessor kid fails its responses closed
//!          (`delegation_revoked`) while the successor's still verify.
//!
//! Both lanes share the offline/live entry-point pattern of the sibling test:
//!   * `*_offline_local_seed` — NOT ignored: the feature-gated CI job runs it via
//!     a local-key `KmsEd25519Backend` (no network), guarding the
//!     KMS-root → serving/flip wiring on every push.
//!   * `*_live` — `#[ignore]`: the real Cloud KMS backend; run from
//!     `work/test-gcp-cloud.sh` (or `docs/security/gcp-kms-delegated-required.sh`)
//!     with `-- --ignored` and `MCP_RE_GCP_*` set. FAILS LOUDLY if unconfigured.
//!
//! Required environment for the live lanes:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;

use crate::delegated_required_lane::run_flip;
use crate::delegated_required_lane::run_serving;
use crate::delegated_required_lane::Lane;
use crate::local_seed_backend::offline_signer;

/// The KMS root's issuer kid == the serving config's --server-key-id. The credential
/// the KMS signs carries this issuer; the verifier resolves it to the KMS public key.
const LANE: Lane = Lane {
    root_kid: "gcp-kms-root-1",
    kms: "Cloud KMS",
};

// --- KMS signer construction (identical policy to the sibling live test) --------

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms delegated-required lane: required env var {name} is not set — this lane must \
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

// ---- offline (hermetic, runs in the feature-gated CI job) ------------------

#[tokio::test]
async fn gcp_kms_delegated_required_serving_offline_local_seed() {
    run_serving(&LANE, offline_signer()).await;
}

#[test]
fn gcp_kms_authority_flip_offline_local_seed() {
    run_flip(&LANE, offline_signer());
}

// ---- live (real Cloud KMS; ignored) ---------------------------------------

#[tokio::test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
async fn gcp_kms_delegated_required_serving_live() {
    run_serving(&LANE, live_signer()).await;
}

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_authority_flip_live() {
    run_flip(&LANE, live_signer());
}
