// SPDX-License-Identifier: Apache-2.0
//! Body evidence blocks for the HTTP profile (ADR-MCPRE-050 §Resolved-owner
//! ruling 1, MCPRE-93).
//!
//! No new HTTP header fields are minted (v0.11 grill E-3): all MCP-specific
//! evidence rides in the JSON-RPC body under a `_meta` key and is protected
//! because `content-digest` is a covered component of the RFC 9421 signature.
//! These are **semantic evidence** blocks — not a custom crypto envelope — and
//! carry **no raw secrets**: authorization artifacts appear only as digests or
//! references (`digest_alg`/`digest_value`, `reference_*`), never token bytes.
//!
//! Two identifiers are pinned here for the replay key (MCPRE-94) and audit:
//!
//! - [`ActorIdentity::actor_id`] — the canonical identity of the signing actor
//!   AFTER trust resolution, including role and trusted key identity (not a raw
//!   keyid alone). Serialized `role:trust_domain:subject:keyid` with each
//!   component escaped so the join is injective.
//! - [`AudienceTuple::audience_hash`] — SHA-256 over the canonical audience
//!   tuple bytes, not merely `@target-uri`, so replay prevention never merges
//!   different MCP audiences that share one HTTP endpoint.

mod actor;
pub mod artifact_binding;
mod audience;
mod continuation;
mod request;
mod response;

pub use actor::ActorIdentity;
pub use actor::ResolvedActor;
pub use actor::ResolverOutcome;
pub use actor::SignerSlot;
pub use artifact_binding::ArtifactBinding;
pub use artifact_binding::ArtifactType;
pub use artifact_binding::BindingType;
pub use audience::AudienceTuple;
pub use continuation::HttpContinuation;
pub use continuation::CONTINUATION_TYPE_MCP_MRT;
pub use request::HttpRequestEvidenceBlock;
pub use response::HttpResponseEvidenceBlock;

/// A base64url-no-pad token: URL-safe alphabet, no `=` padding, non-empty.
pub(crate) fn is_b64url_no_pad(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
