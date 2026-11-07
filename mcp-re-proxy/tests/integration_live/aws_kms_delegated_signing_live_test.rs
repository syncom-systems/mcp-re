// SPDX-License-Identifier: Apache-2.0
//! Live AWS KMS — ADR-MCPRE-052 delegated-signing custody lane
//! (MCPRE-122 / #328).
//!
//! The sibling `aws_kms_http_profile_live_test` proves AWS KMS can sign an
//! RFC 9421 response DIRECTLY — one KMS `Sign` PER response, i.e. the
//! root key is on the hot path. This lane proves the ADR-MCPRE-052 posture that
//! removes it from the hot path: AWS KMS is the root ISSUER that signs only a
//! short-lived compact-JWS **delegation credential** at issuance/rotation, while
//! an in-memory Ed25519 **delegated** key signs the per-request RFC 9421
//! responses. The load-bearing property proven here:
//!
//!   **Zero remote KMS operations on the per-request signing path** — signing N
//!   responses within one delegated key's life invokes AWS KMS exactly once
//!   (the initial issuance), and `verify_delegated_response_full` accepts each
//!   response via the credential's attestation chain back to the KMS root.
//!
//! It wires `AwsKmsEd25519Backend` as the custody root issuer through the
//! wire-identical KMS seam `issue_delegation_credential_with_signer` (the same
//! seam the in-process reference issuer uses), so the KMS is a swap of the
//! injected issuer, not a code fork.
//!
//! Two entry points share one lane body:
//!   * `*_offline_local_seed` — NOT ignored: runs in the blocking feature-gated
//!     CI job via a local-key `KmsEd25519Backend` (no network),
//!     guarding the KMS-backend → custody-issuer wiring on every push.
//!   * `*_live` — `#[ignore]`: the real AWS KMS backend; run from the cloud
//!     script / nightly lane with `-- --ignored` and `MCP_RE_AWS_KMS_*` set. FAILS
//!     LOUDLY if its configuration is absent — never a silent pass.
//!
//! Required environment for the live lane:
//!   * `MCP_RE_AWS_KMS_KEY_ID`   — an `ECC_NIST_EDWARDS25519` key id/ARN/alias.
//!   * `MCP_RE_AWS_KMS_REGION`   — the region.
//!   * Credentials: the static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` pair,
//!     or `MCP_RE_AWS_USE_WEB_IDENTITY=1` for the IRSA path (what the on-EKS run
//!     uses — no IAM key material in the pod).
//!   * `MCP_RE_AWS_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "aws_kms_keysource")]

use mcp_re_proxy::AwsKmsConfig;
use mcp_re_proxy::AwsKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;

use crate::delegated_signing_lane::Lane;
use crate::local_seed_backend::offline_signer;

// The KMS root's `issuer_kid` (the identity anchor the verifier trusts). The
// delegated key ids the custody mints are `<ROOT_KID>/delegated/<n>`.
const ROOT_KID: &str = "aws-kms-root-1";

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "aws-kms delegated-signing lane: required env var {name} is not set — this lane must \
             run against a real/emulated AWS KMS; it does not pass without verifying"
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
    // Either custody path reaches the same KMS key. On EKS the runner takes the
    // IRSA one, so the property this lane proves holds on a pod that contains no
    // IAM key material at all.
    let backend = if std::env::var("MCP_RE_AWS_USE_WEB_IDENTITY").is_ok_and(|v| v == "1") {
        AwsKmsEd25519Backend::from_web_identity(
            &config,
            std::env::var("MCP_RE_AWS_STS_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
        )
        .expect("construct AWS KMS backend through IRSA (GetPublicKey must succeed and be Ed25519)")
    } else {
        require_env("AWS_ACCESS_KEY_ID");
        AwsKmsEd25519Backend::from_env(&config)
            .expect("construct AWS KMS backend (GetPublicKey must succeed and be Ed25519)")
    };
    KmsResponseSigner::new(Box::new(backend))
}

// ---- offline (hermetic, runs in blocking CI) ------------------------------

#[test]
fn aws_kms_delegated_signing_offline_local_seed() {
    Lane::over_root(ROOT_KID).run(offline_signer());
}

// ---- live (real AWS KMS; ignored) ---------------------------------------

#[test]
#[ignore = "requires a live or emulated AWS KMS (run with --ignored and MCP_RE_AWS_KMS_* set)"]
fn aws_kms_delegated_signing_live() {
    Lane::over_root(ROOT_KID).run(live_signer());
}
