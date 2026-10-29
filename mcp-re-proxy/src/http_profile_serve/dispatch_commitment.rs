// SPDX-License-Identifier: Apache-2.0
//! The last five things asked before the backend is reached, in the only order that keeps
//! the durable record honest.
//!
//! Local saturation and a fully-ejected backend set are facts about this proxy, knowable
//! without writing anything, and they are settled first — by TAKING the plane's capacity
//! rather than predicting it, so nothing can refuse on them later.
//!
//! Then the question that needs the capability to exist before it can be asked: does the
//! signing window this exchange already holds survive the worst instant a dispatch under
//! this plane's own bound can complete at? A reply signed under a window the client refuses
//! is a well-formed signature over a dead assertion — the caller learns about it by
//! failing, after the backend has run, and an ordinary retry runs the action twice. Asking
//! before the threshold turns that into a refusal the client can act on, while refusing is
//! still free.
//!
//! What writes comes after, in three steps that are three facts. The retention obligation is
//! ACCEPTED, which asserts nothing about execution and is rescinded by dropping the value
//! that carries it. Then, under the required audit posture, the exchange's execution INTENT
//! is committed and its witness redeemed (ADR-MCPRE-070 G1, D7): after the reserve, so a
//! refused reservation commits no intent, and before the crossing, so no `.pending` marker
//! exists for an exchange whose intent was never committed. Then the crossing is RECORDED,
//! and that recording is the execution threshold: it is the last refusal of any kind, and
//! the request relation says so — `DispatchCommitted` is the state the dispatch leaves from,
//! so a pipeline that recorded the crossing before asking the questions that could still
//! refuse would be rejected by the machine rather than merely recorded oddly.
//!
//! The signing window is asked to survive the intent's bounded wait as well as the
//! dispatch's, because both now lie between the window's single clock reading and the
//! reply it will sign.

use mcp_re_core::McpReError;

use crate::async_serve::ServedHttpResponse;
use crate::audit_record::ExecutionIntent;
use crate::authorization::AuthorizationPosture;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::refusal::Refusal;
use crate::request_stages::ReadyForDispatch;

use super::body_boundary::ForwardedBody;
use super::dispatch_obligations;
use super::receipt::Accepted;
use super::receipt::RefusalPoint;
use super::request_admission::ValidatedRequestEnvelope;
use super::signing_window;
use super::signing_window::SigningWindow;
use super::Exchange;
use super::HttpProfileProxy;

impl HttpProfileProxy {
    /// Serve a refusal past the accepted record: every one is `mcp-re.response.rejected`,
    /// signed under the exchange's own key snapshot.
    pub(super) fn refuse_accepted(
        &self,
        acc: &Accepted<'_>,
        refusal: Refusal,
        progress: &mut ExchangeProgress,
    ) -> ServedHttpResponse {
        let owed = Self::disposition(progress, refusal.execution_refinement);
        self.responses.refuse(
            self.audit.observer(),
            RefusalPoint::Response(acc),
            refusal,
            owed,
        )
    }

    /// FORWARDED — strip the proxy-owned `_meta` so the backend sees clean MCP.
    ///
    /// ```text
    /// ensures   Ok  => a body the inner server may receive, carrying verified context
    ///                  the caller did not author
    ///           Err => 500, bound
    /// forbids   running the backend
    /// refusal   free of execution; the approval may already be spent
    /// ```
    ///
    /// Fails closed when the trusted carrier is on but the context could not be written:
    /// the inner server would otherwise get an ordinary-looking request with no verified
    /// context, which is a silent downgrade to an unauthenticated call.
    fn forward_body_stage(
        &self,
        ex: &Exchange<'_>,
        envelope: &ValidatedRequestEnvelope<'_>,
    ) -> Result<Established<Vec<u8>>, Refusal> {
        let forwarded = ForwardedBody::prepare(
            envelope.body(),
            ex.verified,
            self.verified_context_policy,
            ex.now,
        )
        .map_err(|e| Refusal::new(e, 500))?;
        Ok(Established::new(
            forwarded.into_bytes_for_inner(ex.actor_id),
            ExchangeEvent::ForwardBodyPrepared,
        ))
    }

    /// Assemble the ready state the dispatch consumes, refusing while refusing is still
    /// possible.
    ///
    /// The body is prepared first because preparing it decides nothing; the inner plane is
    /// prepared second because its refusal is free and leaves nothing behind; the signing
    /// window is checked against that plane's completion bound third, because the bound
    /// does not exist until the capability does; the retention obligation is accepted
    /// fourth because it is the first that writes; the intent is committed fifth (G1); and
    /// the crossing is recorded LAST, because recording it is what makes every earlier
    /// refusal free and every later one impossible.
    ///
    /// The inner-plane capability is HELD from here to the dispatch. If the reservation
    /// then refuses, the prepared dispatch is dropped on the way out and everything it took
    /// — the in-flight permit, any claimed recovery probe — goes back without a release
    /// call. That is why the ordering is safe to state as an ordering: nothing between the
    /// two steps can leak the plane's capacity, and nothing after the reservation can
    /// refuse.
    pub(super) async fn commit_to_dispatch<'p>(
        &'p self,
        acc: &Accepted<'_>,
        envelope: &ValidatedRequestEnvelope<'_>,
        authorized: AuthorizationPosture,
        window: SigningWindow,
        progress: &mut ExchangeProgress,
    ) -> Result<ReadyForDispatch<'p>, ServedHttpResponse> {
        let forwarded = match self.forward_body_stage(acc.exchange(), envelope) {
            Ok(body) => progress.establish(body),
            Err(refusal) => return Err(self.refuse_accepted(acc, refusal, progress)),
        };
        let prepared = match self.inner_async.prepare(authorized.release(forwarded)) {
            Ok(prepared) => progress.establish(prepared),
            Err(refusal) => return Err(self.refuse_accepted(acc, refusal, progress)),
        };
        // The signing window must still be admissible at the worst instant this dispatch
        // can complete at, after the intent crossing's own bounded wait — asked HERE because
        // this is the first point where the bound exists and the last where refusing is
        // free. The capability is already held, so a refusal drops it and returns everything
        // it took.
        let completion = prepared
            .completion_bound()
            .after(self.audit.pre_dispatch_wait());
        if !signing_window::covers(&window, completion) {
            return Err(self.refuse_accepted(
                acc,
                Refusal::new(McpReError::DelegatedSigningUnavailable, 503),
                progress,
            ));
        }
        // ADR-MCPRE-070 D7. A refusal drops `prepared`, which returns the plane's capacity,
        // and the obligations taken so far rescind themselves: nothing is left behind.
        let ex = acc.exchange();
        let intent = ExecutionIntent::new(ex.actor_id, ex.now);
        let obligations = dispatch_obligations::take(
            &self.retention,
            &self.audit,
            ex.http_req,
            acc.exchange_coordinate(),
            intent,
        );
        let (retention, intent) = match obligations.await {
            Ok((crossing, intent)) => (progress.establish(crossing), intent),
            Err(refusal) => return Err(self.refuse_accepted(acc, refusal, progress)),
        };
        Ok(ReadyForDispatch::new(prepared, window, retention, intent))
    }

    /// Serve under `audit`, the posture the composition root established. Crate-wide: only
    /// the root holds one; an embedder installs an observer with `with_audit_sink`.
    pub(crate) fn with_audit_posture(
        mut self,
        audit: crate::audit_commitment::AuditPosture,
    ) -> Self {
        self.audit = audit;
        self
    }

    /// Require a committed execution intent before every dispatch, committed to the scripted
    /// `reference` authority within `bound` (ADR-MCPRE-070 G1), keeping the observer.
    ///
    /// Established exactly as startup establishes a provider (`establish_reference`). Test
    /// builds and the test-only `audit_commitment_reference` feature only: `pub` because the
    /// serving integration suites are another crate, and no deployable library compiles it.
    #[cfg(any(test, feature = "audit_commitment_reference"))]
    pub fn with_required_audit_commitment(
        mut self,
        reference: &crate::audit_commitment::ReferenceCommitment,
        bound: std::time::Duration,
    ) -> Result<Self, String> {
        let (provider, bound) = crate::audit_commitment::establish_reference(reference, bound)?;
        let observer = self.audit.observer().clone();
        self.audit = crate::audit_commitment::AuditPosture::required(observer, provider, bound);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::ExchangeEvent;
    use crate::exchange_state::transition;
    use crate::exchange_state::ExchangeState;

    /// The order this region asks in is the relation's, not a local convention. A pipeline
    /// that recorded the crossing before asking the questions that can still refuse would
    /// be rejected by the machine rather than merely leaving an odd record.
    #[test]
    fn the_crossing_is_recorded_after_everything_that_can_refuse_and_before_the_dispatch() {
        assert!(transition(
            ExchangeState::InnerPlaneAccepted,
            ExchangeEvent::RetentionCommitted
        )
        .is_ok());
        assert!(transition(
            ExchangeState::RetentionCommitted,
            ExchangeEvent::BackendDispatched
        )
        .is_ok());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::BackendDispatched).is_err());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::RetentionCommitted).is_err());
    }

    /// A refusal is free right up to the crossing, and never after it.
    ///
    /// The predicate the two-stage store buys. Under one artefact the machine could not
    /// say this: the only pre-dispatch state that wrote anything wrote the thing an auditor
    /// reads as a crossing, so *refusing here is free* and *this may have executed* were
    /// true of the same state.
    #[test]
    fn the_last_state_that_can_refuse_freely_is_the_one_before_the_crossing() {
        assert!(!ExchangeState::InnerPlaneAccepted.backend_may_have_executed());
        assert!(ExchangeState::RetentionCommitted.backend_may_have_executed());
    }
}
