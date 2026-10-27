// SPDX-License-Identifier: Apache-2.0
//! The one success exit: a success becomes visible only after its outcome is committed and its
//! retention has completed (ADR-MCPRE-070 G2, S2, D4, Q2; ADR-MCPRE-054).
//!
//! ```text
//! may_publish(success)        decided by the caller, before anything publishes the claim
//!   └─ G2: outcome committed  ── refused ──> 500 audit_commitment_unavailable; retention
//!        │                                   completion attempted with that refusal (W5)
//!        └─ retention completes ── failed ──> 500 evidence_retention_indeterminate (W5b)
//!             └─ the observer is offered the record, the terminal is published, served
//! ```
//!
//! Every success terminal comes through here — the bodied reply's two and the bodyless 202 —
//! so the order is one function rather than two copies of it. Every refusal on the way out is served
//! from a machine that has crossed the dispatch and never claimed success, so it states
//! `PossiblyExecuted` — never `NothingExecuted`, and never the success bytes.
//!
//! The order is in the types. Each step takes the previous step's product by value and the
//! products are private to this module: [`Committed`] is made only by the outcome commitment
//! and [`Retained`] only by completed retention, so retention cannot run before G2, nothing
//! can be served before retention, and a refusing step leaves nothing for the next one to
//! take. The last step offers, publishes and serves with no await and no refusal between them.
//!
//! Under the best-effort posture the order and the bytes are unchanged: G2 passes the
//! posture's statement through, and the `response.signed` record is produced when the
//! response is served, as before.

use mcp_re_http_profile::HttpResponse;

use crate::async_serve::ServedHttpResponse;
use crate::audit_record::{AuditRecord, AuditSubject};
use crate::exchange_state::publication::PublishPermit;
use crate::request_stages::{OutcomeDisposition, PostDispatch, RetentionDisposition};

use super::super::inner_plane::NotificationDelivered;
use super::super::receipt::Accepted;
use super::super::served;
use super::super::HttpProfileProxy;

/// A cleared success whose outcome G2 committed: what retention completes over.
struct Committed<'x> {
    permit: PublishPermit<'x, NotificationDelivered>,
    response: HttpResponse,
    retention: RetentionDisposition,
    outcome: OutcomeDisposition,
    observed: AuditRecord,
}

/// A committed success whose retention completed: all that is left is to serve it.
struct Retained<'x> {
    permit: PublishPermit<'x, NotificationDelivered>,
    response: HttpResponse,
    outcome: OutcomeDisposition,
    observed: AuditRecord,
}

impl HttpProfileProxy {
    /// Commit the outcome, complete retention, offer the record, reach the terminal, serve.
    ///
    /// The only place a success is `served`. The caller has already decided
    /// `may_publish(success)`: the permit is its answer.
    pub(super) async fn publish_success(
        &self,
        acc: &Accepted<'_>,
        permit: PublishPermit<'_, NotificationDelivered>,
        response: HttpResponse,
        owed: PostDispatch,
    ) -> ServedHttpResponse {
        let committed = match self.commit_outcome(acc, permit, response, owed).await {
            Ok(committed) => committed,
            Err(refused) => return refused,
        };
        match self.complete_retention(acc, committed).await {
            Ok(retained) => self.serve_published(acc, retained),
            Err(refused) => refused,
        }
    }

    /// G2, BEFORE retention completes (Q2): a refusal here is what retention then holds, so
    /// the retained representation stays the one actually served. The intent G1 carried is
    /// what G2 commits through; neither the posture nor the coordinate is read here.
    async fn commit_outcome<'x>(
        &self,
        acc: &Accepted<'_>,
        permit: PublishPermit<'x, NotificationDelivered>,
        response: HttpResponse,
        owed: PostDispatch,
    ) -> Result<Committed<'x>, ServedHttpResponse> {
        let (retention, intent) = owed.into_publication();
        let observed = AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some(acc.exchange().actor_id.to_owned()),
            status: response.status,
            at_unix: acc.exchange().now,
        };
        match intent.outcome(observed.clone()).await {
            Ok(outcome) => Ok(Committed {
                permit,
                response,
                retention,
                outcome,
                observed,
            }),
            Err(refusal) => Err(self
                .refuse_retained(acc, refusal, permit.exchange(), &retention)
                .await),
        }
    }

    /// Retain the committed success (ADR-MCPRE-054), or refuse it.
    ///
    /// Before the response goes out or its `response.signed` record is offered: retaining an
    /// exchange the client never received would put a record in the store that no receipt
    /// should be issued about.
    async fn complete_retention<'x>(
        &self,
        acc: &Accepted<'_>,
        committed: Committed<'x>,
    ) -> Result<Retained<'x>, ServedHttpResponse> {
        let Committed {
            permit,
            response,
            retention,
            outcome,
            observed,
        } = committed;
        if self
            .retention
            .complete(&retention, &response)
            .await
            .is_accounted_for()
        {
            return Ok(Retained {
                permit,
                response,
                outcome,
                observed,
            });
        }
        // The call executed and the record did not land. INDETERMINATE, and deliberately
        // not 503: the backend has already run, and 503 is the status clients retry.
        let refusal = crate::refusal::Refusal::new(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate,
            500,
        );
        Err(self.refuse_accepted(acc, refusal, permit.exchange()))
    }

    /// Offer the record, reach the terminal the permit names, and serve the bytes.
    fn serve_published(&self, acc: &Accepted<'_>, retained: Retained<'_>) -> ServedHttpResponse {
        self.offer_outcome(acc, &retained.outcome, retained.observed);
        retained.permit.publish();
        served(retained.response)
    }

    /// Offer the success record to the observer. The record describes bytes the client
    /// receives, so it is offered on the way out — and under the required posture it is the
    /// committed event itself, not a second one.
    fn offer_outcome(
        &self,
        acc: &Accepted<'_>,
        outcome: &OutcomeDisposition,
        observed: AuditRecord,
    ) {
        if let OutcomeDisposition::Committed(committed) = outcome {
            crate::audit_record::offer_produced(self.audit.observer(), committed.envelope());
        } else {
            crate::audit_record::record_to(
                self.audit.observer(),
                acc.exchange_coordinate(),
                observed.subject,
                observed.actor_id,
                observed.status,
                observed.at_unix,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    /// The success exit is the only place in the reply region that serves a success.
    ///
    /// A source scan, because `ServedHttpResponse` is the serving seam's public type with
    /// public fields and `served` is visible to the whole serving module: no type in this
    /// region can stop a second success from being served, so the scan makes one visible.
    #[test]
    fn success_exit_is_the_only_success_served_call() {
        for (name, source) in [
            ("accepted.rs", include_str!("accepted.rs")),
            ("dispatched.rs", include_str!("dispatched.rs")),
            ("notification.rs", include_str!("notification.rs")),
            ("mod.rs", include_str!("mod.rs")),
        ] {
            let production = source.split("#[cfg(test)]").next().unwrap_or(source);
            assert!(
                !production.contains("served("),
                "{name} serves bytes itself; a success leaves through publish_success"
            );
        }
        let exit = include_str!("success_exit.rs");
        let production = exit.split("#[cfg(test)]").next().unwrap_or(exit);
        assert_eq!(production.matches("served(").count(), 1);
    }
}
