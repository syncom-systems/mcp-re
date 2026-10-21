// SPDX-License-Identifier: Apache-2.0
//! The seam a commitment provider implements.

use std::future::Future;
use std::pin::Pin;

use super::{
    CommitRequest, CommitmentReceipt, DurabilityTier, EstablishFailure, ProviderFailure, ProviderId,
};

/// A provider's answer, boxed and `Send` so the seam is object-safe and the answer can be
/// awaited inside a request future (the `AsyncAtomicReplayStore` precedent: native
/// async-fn-in-trait is not `dyn`-compatible).
pub type CommitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CommitmentReceipt, ProviderFailure>> + Send + 'a>>;

/// A provider's answer to being established, boxed and `Send` for the same reason.
pub type EstablishFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), EstablishFailure>> + Send + 'a>>;

/// A required durable commitment authority (ADR-MCPRE-070 §2).
///
/// A separate contract from the observer [`crate::audit_sink::AuditSink`]: a sink returns
/// nothing and absorbs its failures, while an authority answers every request with a
/// receipt or a typed failure, and its answer is never absorbed. What it answers is a
/// CLAIM — the shared owner [`super::EstablishedProvider`] checks a receipt against the
/// request it sent before it mints a witness, and whether the provider persisted anything
/// is an assumption with external evidence, never a consequence of an `Ok` (D3).
///
/// # The embedder contract (`pub`, #1206)
///
/// An independently compiled provider implements this trait and is registered through
/// [`super::AuditProviders`]; nothing else about it is visible to the shared code. Its
/// settings and secrets are its own — taken by its constructor, from its environment or its
/// files — and never pass through the proxy's configuration or diagnostics. What it can
/// produce is a [`CommitmentReceipt`], a [`ProviderFailure`] or an [`EstablishFailure`]; it
/// cannot produce a witness, and nothing it returns is evidence of persistence.
///
/// **`Drop` is in-process only.** The proxy reclaims a provider after the fleet has
/// drained (ADR-MCPRE-056 §10): releasing handles is fine, waiting on the outside world is
/// not, because that time is taken from the drain grace period the deployment budgets. A
/// receipt is returned only once the event is committed at the declared tier, so there is
/// nothing to flush.
pub trait CommitmentAuthority: Send + Sync {
    /// The name the posture line and the shutdown report print. Read once, at startup.
    fn provider_id(&self) -> ProviderId;

    /// The tier this provider declares. Read ONCE, when it is established. There is no
    /// default: an authority that forgot to declare and one that declared volatility must
    /// not be the same fact.
    fn declared_tier(&self) -> DurabilityTier;

    /// Connect, authenticate and probe, once, at startup. The shared owner bounds the wait
    /// and catches a panic; a failure, a timeout or a panic refuses startup, and the
    /// required posture is never served over a provider that did not establish (S4).
    fn establish(&self) -> EstablishFuture<'_>;

    /// Commit `request`. The returned future is polled on the request path, inside the
    /// request's own future: it MUST NOT perform synchronous storage I/O on the polling
    /// thread. A provider that writes synchronously hands the write to a worker it owns and
    /// awaits that worker's acknowledgement (the `transparency::durability` precedent).
    fn commit<'a>(&'a self, request: CommitRequest<'a>) -> CommitFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::reference::ReferenceAuthority;

    /// The seam is object-safe and shareable across a core's connections.
    #[test]
    fn the_seam_is_object_safe_send_and_sync() {
        fn shareable<T: Send + Sync + ?Sized>() {}
        shareable::<dyn CommitmentAuthority>();
        let authority: Box<dyn CommitmentAuthority> =
            Box::new(ReferenceAuthority::new(DurabilityTier::ProcessVolatile));
        assert_eq!(authority.declared_tier(), DurabilityTier::ProcessVolatile);
        assert!(authority.provider_id().is_reference());
    }
}
