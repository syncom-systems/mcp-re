// SPDX-License-Identifier: Apache-2.0
//! The multi-round-trip continuation plane (ADR-MCPS-047, MRTR).
//!
//! One fact: **a human's approval is opened, read without being spent, spent exactly once,
//! and recorded so that any replica can answer it.** The operations that make that sentence
//! true were spread across the serving assembly's stages, with the store and its TTL held
//! as two fields beside fourteen unrelated ones.
//!
//! # The two legs, and why they are separate files
//!
//! | leg | what it does | refusal |
//! |---|---|---|
//! | [`answer_leg`] | reads a live approval, then SPENDS it | free until the consume; the consume is the spend |
//! | [`open_leg`] | CREATES an approval the next leg will answer | never free — the backend has already run |
//!
//! Those are opposite consequences, and the split is at that boundary rather than at one
//! module per operation. A refusal on the answer leg's read leaves the approval intact and
//! an ordinary retry works; a refusal on the open leg happens past the execution threshold
//! and no retry can undo what the backend did.
//!
//! # What this owner keeps from being collapsed
//!
//! * a store MISS, a store OUTAGE and an ABSENT CAPABILITY are different facts. A miss is
//!   a statement about the caller (never opened, expired, already answered); an outage and
//!   a deployment that selected no correlation store are statements about this deployment.
//!   Flattening them reports a forged continuation every time the shared tier blips — or
//!   for every legitimate answer leg reaching a deployment without the capability — and
//!   hides a genuine splice attempt inside both.
//! * the read is a `peek`, never a `consume`, so a request that is about to be refused
//!   leaves a live approval intact.
//! * retirement has FOUR outcomes, because the store's `Err` is not its `Ok(false)`.
//!
//! # One owner of correlation lookup
//!
//! Key derivation, the read, the binding, the open-leg record and the retirement verdict
//! all live here, and every caller goes through this plane: the serving assembly, and the
//! HTTP-profile proof front (`examples/http_profile_proxy.rs`). The binding a caller hands
//! to replay admission ([`ContinuationPrep::binding`]) is only ever built from handles read
//! under the key derived from THIS request's verifier-resolved actor and `requestState`,
//! which is the half of the binding `RetainedContinuation` itself cannot see.
//!
//! What this owner does NOT do is record what the EXCHANGE may claim about an approval.
//! That needs the exchange machine's cross-machine state, which no stage holds; the
//! assembly reads [`Retirement::may_have_spent`] into that machine before it signs the
//! [`Retirement::refusal`].
//!
//! # Why the plane is public
//!
//! The proof front is a separate target, run by the proof scripts and the SDK end-to-end
//! tests. While the plane was private to the serving path the front re-derived the whole
//! sequence, and its copy read a store outage as a forged continuation. The public surface
//! is the three operations and their outcomes; the store and the key never leave the plane.

use std::sync::Arc;

use crate::continuation_store::AsyncContinuationStore;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::http_profile_serve::request_admission::ValidatedRequestEnvelope;
use crate::http_profile_serve::Exchange;
use crate::refusal::Refusal;

/// Reading a live approval and spending it — the leg that ANSWERS an elicitation.
mod answer_leg;
/// Recording a new approval so any replica can answer it — the leg that OPENS one.
mod open_leg;
/// What a leg is refused with, classified once for every caller.
mod refusal;
/// Spending a read approval exactly once, and reporting what the tier said — RETIREMENT.
mod retirement;

pub use answer_leg::ContinuationPrep;
pub use refusal::ContinuationRefusal;
pub use retirement::Retirement;

/// The deployment's continuation plane: the shared correlation tier, and the bounded
/// lifetime every entry it writes runs under.
///
/// Private representation with two constructors, so *this deployment runs no store* is a
/// state of the plane rather than a `None` the assembly carries beside a TTL that then
/// means nothing. Both legs are implemented on this type in their own modules, which reach
/// the two fields as children of this one — the store is never handed out.
pub struct ContinuationPlane {
    /// The fleet-shared tier that carries a multi-round-trip continuation across a replica
    /// switch, when the deployment selected one. `None` means MRTR continuation
    /// correlation is unavailable in this deployment — no store is installed and none is
    /// substituted — so the open leg refuses rather than returning an elicitation nothing
    /// was kept for, and an answer leg that needs correlation is refused as a fact about
    /// this deployment rather than as the caller's forged continuation.
    store: Option<Arc<dyn AsyncContinuationStore>>,
    /// Lifetime of a recorded continuation in seconds; positive by type.
    ttl: std::num::NonZeroU32,
}

impl ContinuationPlane {
    /// The plane of a deployment that runs no correlation store.
    pub fn disabled() -> Self {
        ContinuationPlane {
            store: None,
            ttl: super::DEFAULT_CONTINUATION_TTL_SECS,
        }
    }

    /// The plane of a deployment that wired one, with the bounded entry TTL it chose.
    pub fn wired(store: Arc<dyn AsyncContinuationStore>, ttl: std::num::NonZeroU32) -> Self {
        ContinuationPlane {
            store: Some(store),
            ttl,
        }
    }

    /// CONTINUATION-PREPARED, as the serving assembly's exchange machine records it: the
    /// answer leg read through [`ContinuationPlane::read_answer`].
    pub(in crate::http_profile_serve) async fn prepare(
        &self,
        ex: &Exchange<'_>,
        envelope: &ValidatedRequestEnvelope<'_>,
        audience_id: &str,
    ) -> Result<Established<ContinuationPrep>, Refusal> {
        let prep = self
            .read_answer(ex.verified, envelope.body(), audience_id)
            .await?;
        Ok(Established::new(prep, ExchangeEvent::ContinuationPrepared))
    }

    /// CONTINUATION-RECORDED, as the serving assembly's exchange machine records it: the
    /// open leg recorded through [`ContinuationPlane::record_open`].
    pub(in crate::http_profile_serve) async fn record_open_leg(
        &self,
        ex: &Exchange<'_>,
        audience_id: &str,
        state: &str,
        response_base: Vec<u8>,
    ) -> Result<Established<()>, Refusal> {
        self.record_open(ex.verified, audience_id, state, response_base)
            .await?;
        Ok(Established::new((), ExchangeEvent::OpenLegRecorded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_plane_still_carries_the_default_lifetime() {
        // The TTL is not conditional on there being a store. Holding it here rather than
        // beside an `Option` in the assembly is what stops a deployment from configuring a
        // lifetime for entries nothing will ever write.
        let plane = ContinuationPlane::disabled();
        assert!(plane.store.is_none());
        assert_eq!(plane.ttl, super::super::DEFAULT_CONTINUATION_TTL_SECS);
    }
}
