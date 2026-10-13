// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-binding-core` — the one adapter both SDK bindings share over the audited
//! `mcp-re-client-core` RFC 9421 signing and verification seam (ADR-MCPS-044).
//!
//! The PyO3 binding (`sdk/python`) and the napi binding (`sdk/typescript`) marshal host
//! values into the typed arguments here and marshal the results back; everything they
//! used to restate lives here once: the signing inputs and their refusal order, the device
//! signature check, the root-issuer anchor, the verify preamble, the verdict projection,
//! and the one rendering of a wire refusal.
//!
//! No host language is linked: this crate depends on neither PyO3 nor napi, which is what
//! lets both bindings consume it and what keeps language bindings out of
//! `mcp-re-client-core`.

mod error;
mod pinned_issuer;
mod sign;
mod sign_args;
mod verdict;
mod verify;
mod verify_args;

pub use error::BindingError;
pub use error::IssuerField;
pub use pinned_issuer::PinnedIssuer;
pub use sign::sign;
pub use sign::sign_preimage;
pub use sign::sign_with_device;
pub use sign::SignedParts;
pub use sign_args::Call;
pub use sign_args::ContinuationArgs;
pub use sign_args::SignArgs;
pub use verdict::Verdict;
pub use verify::verify_accepted_202;
pub use verify::verify_response;
pub use verify::Acceptance;
pub use verify_args::VerifyArgs;

/// The audited core's version: `mcp-re-client-core`'s, not a binding crate's.
pub use mcp_re_client_core::CORE_VERSION;
/// The RFC 9421 profile tag the signature is emitted and verified under.
pub use mcp_re_client_core::PROFILE_TAG;

/// The widest clock-skew tolerance, in seconds, a verification call accepts: the profile's
/// own bound, exported so a host derives every window it keeps from the number the core
/// enforces rather than restating it.
pub const MAX_CLOCK_SKEW_BOUND_SECS: i64 = mcp_re_core::MaxClockSkew::BOUND_SECS;
