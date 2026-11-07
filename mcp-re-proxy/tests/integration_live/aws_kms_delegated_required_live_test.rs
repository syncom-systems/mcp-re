// SPDX-License-Identifier: Apache-2.0
//! Live AWS KMS — ADR-MCPRE-052 delegated-REQUIRED serving + authority-flip lanes.
//! The AWS counterpart of `gcp_kms_delegated_required_live_test`, proving the SAME
//! semantic chain against a real AWS KMS root.
//!
//! `aws_kms_live_test` proves only that a real KMS `Sign` verifies under
//! `mcp-re-core`. That does NOT reach the delegated authority: under ADR-MCPRE-052
//! the root never signs a response — it ISSUES a short-TTL credential, and an
//! in-memory delegated key signs the operational response. This lane proves that
//! chain, and is therefore the lane the cross-cloud delegated-root claim rests on.
//!
//!   * **Serving** — drives the PRODUCTION wiring `build_delegated_signing(config,
//!     kms_root)` + `HttpProfileProxy::new_delegated` — the exact path `app::run`
//!     takes for delegated-signing (the only response mode) — and serves real
//!     requests through the PEP. The KMS root is wrapped in a counting
//!     `ResponseSigner` so the load-bearing property is asserted at the SERVING
//!     altitude: N served responses invoke AWS KMS ZERO extra times (one op per
//!     key issuance/rotation, none per request). Also proves rotation to a
//!     successor and the client revocation seam (allow + deny) on a KMS-rooted
//!     credential.
//!
//!   * **Authority flip** — on ONE KMS key:
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
//! Entry points follow the offline/live pattern of the GCP sibling:
//!   * `*_offline_local_seed` — NOT ignored: the feature-gated CI job runs it via
//!     a local-key `KmsEd25519Backend` (no network, no AWS credentials), guarding the KMS-root → serving/flip wiring on every push.
//!     This is wiring coverage, NOT AWS validation; only the live twin earns that.
//!   * `*_live` — `#[ignore]`: the real AWS KMS backend. FAILS LOUDLY if
//!     unconfigured; it never silently passes without verifying.
//!
//! Required environment for the live lanes:
//!   * `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN` if
//!     temporary) — the static credentials (ADR-MCPS-028 credential scope).
//!   * `MCP_RE_AWS_KMS_KEY_ID`   — an `ECC_NIST_EDWARDS25519` KMS key id/ARN/alias.
//!   * `MCP_RE_AWS_KMS_REGION`   — the region.
//!   * `MCP_RE_AWS_KMS_ENDPOINT` — OPTIONAL endpoint override.
#![cfg(feature = "aws_kms_keysource")]

use mcp_re_proxy::AwsKmsConfig;
use mcp_re_proxy::AwsKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;

use crate::delegated_required_lane::run_flip;
use crate::delegated_required_lane::run_serving;
use crate::delegated_required_lane::Lane;
use crate::local_seed_backend::offline_signer;

/// The KMS root's issuer kid == the serving config's --server-key-id. The credential
/// the KMS signs carries this issuer; the verifier resolves it to the KMS public key.
const LANE: Lane = Lane {
    root_kid: "aws-kms-root-1",
    kms: "AWS KMS",
};

// --- KMS signer construction (identical policy to the sibling live test) --------

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "aws-kms delegated-required lane: required env var {name} is not set — this lane must \
             run against a real AWS KMS; it does not pass without verifying"
        ),
    }
}

/// The live AWS KMS signer (root issuer), failing loudly if unconfigured.
fn live_signer() -> KmsResponseSigner {
    let config = AwsKmsConfig {
        region: require_env("MCP_RE_AWS_KMS_REGION"),
        key_id: require_env("MCP_RE_AWS_KMS_KEY_ID"),
        endpoint: std::env::var("MCP_RE_AWS_KMS_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    // `from_env` reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
    // and performs GetPublicKey (which fails closed unless the key is Ed25519).
    let backend = AwsKmsEd25519Backend::from_env(&config)
        .expect("construct AWS KMS backend (GetPublicKey must succeed and be Ed25519)");
    KmsResponseSigner::new(Box::new(backend))
}

// ---- offline (hermetic, runs in the feature-gated CI job) ------------------

#[tokio::test]
async fn aws_kms_delegated_required_serving_offline_local_seed() {
    run_serving(&LANE, offline_signer()).await;
}

#[test]
fn aws_kms_authority_flip_offline_local_seed() {
    run_flip(&LANE, offline_signer());
}

// ---- live (real AWS KMS; ignored) -----------------------------------------

#[tokio::test]
#[ignore = "requires a live AWS KMS (run with --ignored and MCP_RE_AWS_KMS_* + AWS creds set)"]
async fn aws_kms_delegated_required_serving_live() {
    run_serving(&LANE, live_signer()).await;
}

#[test]
#[ignore = "requires a live AWS KMS (run with --ignored and MCP_RE_AWS_KMS_* + AWS creds set)"]
fn aws_kms_authority_flip_live() {
    run_flip(&LANE, live_signer());
}
