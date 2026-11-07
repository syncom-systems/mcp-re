// SPDX-License-Identifier: Apache-2.0
//! The delegated-REQUIRED serving and authority-flip lanes (ADR-MCPRE-052), shared by the AWS
//! and GCP KMS suites.
//!
//! Both clouds prove the SAME semantic chain against a KMS root: the root never signs a
//! response, it ISSUES a short-TTL credential and an in-memory delegated key signs. What
//! differs between the suites is only how the root signer is constructed and what the root
//! is called, which [`Lane`] carries; the chain itself is stated once, here.
//!
//!   * [`run_serving`] drives the PRODUCTION wiring `build_delegated_signing(plan, root)` +
//!     `HttpProfileProxy::new_delegated` and asserts, at the SERVING altitude, that N
//!     served responses invoke the KMS ZERO extra times.
//!   * [`run_flip`] flips the response authority on ONE KMS key: the pre-052 direct-root
//!     response is refused, the post-052 delegated authority is accepted, a trust-epoch
//!     flip rejects then accepts under a rollout window, and a key rotation plus
//!     revocation fails the predecessor closed while the successor still verifies.
#![cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]

mod fixtures;
mod flip;
mod judge;
mod serving;

pub(crate) use flip::run_flip;
pub(crate) use serving::run_serving;

/// The cloud a lane runs against: the issuer kid its root signs under, and how its KMS is
/// named in assertion messages.
pub(crate) struct Lane {
    pub(crate) root_kid: &'static str,
    pub(crate) kms: &'static str,
}
