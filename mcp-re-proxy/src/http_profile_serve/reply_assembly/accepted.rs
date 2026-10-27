// SPDX-License-Identifier: Apache-2.0
//! Discharging the durable responsibility taken before the dispatch, and reaching a success
//! terminal.
//!
//! The reservation was taken while refusing was still free; this is where it is completed
//! with what was actually served. A deployment with retention on asserts it can account for
//! what it served, and refusing when the evidence cannot be kept is the only thing that keeps
//! that true — so retention completes BEFORE the response goes out and before its
//! `response.signed` record, and after its outcome is committed (ADR-MCPRE-070 Q2).
//!
//! Both success exits retain through here, the bodied reply and the bodyless 202 alike. It is
//! one function and not a block copied twice because retention wired onto only one of them is
//! a client-selectable guarantee, not a weaker one.

use mcp_re_http_profile::HttpResponse;

use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::ServedSuccess;
use crate::request_stages::{PostDispatch, RetentionDisposition};

use super::super::receipt::Accepted;
use super::super::reply::ReplyClass;
use super::super::HttpProfileProxy;
use super::SignedReply;

impl HttpProfileProxy {
    /// Decide the terminal the classifier selected, then leave through the success exit.
    ///
    /// The observer's `response.signed` line is offered only on the way out, not at signing
    /// time: everything before it can still discard this response. Under the required posture
    /// the committed outcome is a different statement — what the proxy observed and signed,
    /// never that it was served (ADR-MCPRE-070 Q2).
    pub(in crate::http_profile_serve) async fn serve_retained(
        &self,
        acc: &Accepted<'_>,
        progress: &mut ExchangeProgress,
        reply: SignedReply,
        owed: PostDispatch,
    ) -> ServedHttpResponse {
        // Two terminals, because the exchange makes a different claim in each: one says the
        // call is over, the other says the client may continue — and the second is only
        // reachable now that the continuation it depends on is durable.
        let success = match reply.class {
            ReplyClass::Terminal => ServedSuccess::Terminal,
            ReplyClass::Open(_) => ServedSuccess::OpenLeg,
        };
        // BEFORE anything publishes the claim. The outcome commitment, retention and the
        // `response.signed` record are all assertions that this exchange succeeded, so a
        // tuple the machine cannot vouch for has to be caught while a refusal is still
        // reachable — which is why this is not a `debug_assert!` and not a check after the fact.
        let Ok(permit) = progress.may_publish(success) else {
            let refusal = crate::refusal::Refusal::new(
                mcp_re_core::McpReError::ExchangeInvariantViolation,
                500,
            );
            return self
                .refuse_retained(acc, refusal, progress, owed.retention())
                .await;
        };
        self.publish_success(acc, permit, reply.response, owed)
            .await
    }

    /// Retain a POST-DISPATCH REFUSAL as the terminal this exchange actually served, and
    /// serve it whatever the retention outcome.
    ///
    /// The marker's meaning is *this request crossed the execution threshold AND no durable
    /// retained terminal exchange discharges that responsibility.* A refusal the proxy
    /// minted and can make durable discharges it exactly as a reply does: the archive then
    /// records what happened, and the marker clears. Leaving it instead would let any caller
    /// who can produce a post-dispatch refusal on demand — an unrecognised `resultType`
    /// yields 502 — accumulate *indeterminate* crossings at will, drowning the signal the
    /// marker exists to carry in the cheapest thing a caller can do.
    ///
    /// **The ordering inverts here, and it has to.** On a success exit retention runs first
    /// and a failure REFUSES. A refusal exit cannot refuse: there is no further exit to fall
    /// through to, and converting one refusal into another loses the cause the client needs.
    /// So the refusal is minted, retention is attempted, and the refusal is served — and a
    /// `Failed` outcome leaves the marker, which under the invariant above is the true
    /// statement about the exchange rather than a failure to clean up.
    ///
    /// Nothing here weakens what the refusal CLAIMS. `ExecutionDisposition` is untouched, so
    /// a retained refusal hop records *the backend may have executed and this is what the
    /// client was told* — more than the store holds today, not less.
    pub(in crate::http_profile_serve) async fn refuse_retained(
        &self,
        acc: &Accepted<'_>,
        refusal: crate::refusal::Refusal,
        progress: &ExchangeProgress,
        retention_owed: &RetentionDisposition,
    ) -> ServedHttpResponse {
        let rejection = self.refuse_accepted(acc, refusal, progress);
        let served_bytes = HttpResponse {
            status: rejection.status,
            headers: rejection.headers.clone(),
            body: rejection.body.clone(),
        };
        // Best effort, and the outcome is CONSUMED rather than dropped — `RetentionOutcome`
        // is `#[must_use]` precisely so a terminal cannot silently forget whether what it
        // served is accounted for.
        let _accounted = self
            .retention
            .complete(retention_owed, &served_bytes)
            .await
            .is_accounted_for();
        rejection
    }

    /// Retain one ACCEPTED exchange (ADR-MCPRE-054), or produce the refusal.
    ///
    /// `Some(rejection)` means the evidence could not be kept and the exchange must be
    /// refused; `None` means it is retained, or retention is not configured, and the
    /// caller may serve.
    ///
    /// EVERY SUCCESS exit reaches it through
    /// [`publish_success`](Self::publish_success), after the outcome is committed and before
    /// the response goes out or its `response.signed` record is offered: retaining an
    /// exchange the client never received would put a record in the store that no receipt
    /// should be issued about. A REFUSAL exit cannot use it — refusing a refusal has no exit
    /// to fall through to — so those go through [`refuse_retained`](Self::refuse_retained).
    pub(super) async fn retain_accepted(
        &self,
        acc: &Accepted<'_>,
        response: &HttpResponse,
        retention_owed: &RetentionDisposition,
        progress: &ExchangeProgress,
    ) -> Option<ServedHttpResponse> {
        if self
            .retention
            .complete(retention_owed, response)
            .await
            .is_accounted_for()
        {
            return None;
        }
        // The call executed and the record did not land. INDETERMINATE, and deliberately
        // not 503: the backend has already run, and 503 is the status clients retry.
        let refusal = crate::refusal::Refusal::new(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate,
            500,
        );
        Some(self.refuse_accepted(acc, refusal, progress))
    }
}

#[cfg(test)]
mod tests {
    /// The refusal a publication failure serves, asserted whole.
    ///
    /// Not merely that it refuses. `mcp-re.exchange_invariant_violation` says *this
    /// deployment's execution no longer satisfied its exchange model — a transition was
    /// illegal, or the resulting cross-machine state was incoherent*, at 500 because the
    /// fault is the proxy's and served through `Accepted` because the request verified and crossed
    /// the execution threshold. And
    /// `execution_refinement` is `None`: the refusal states nothing about whether the
    /// backend ran, so the exchange machine's derivation stands — which, with the anomaly
    /// latched, is `possibly_executed`.
    #[test]
    fn the_publication_refusal_says_the_proxy_disagreed_with_itself_and_nothing_about_the_backend()
    {
        let refusal =
            crate::refusal::Refusal::new(mcp_re_core::McpReError::ExchangeInvariantViolation, 500);
        assert_eq!(
            refusal.cause.wire_code(),
            "mcp-re.exchange_invariant_violation"
        );
        assert_eq!(refusal.status, 500);
        assert_eq!(refusal.execution_refinement, None);
    }
}
