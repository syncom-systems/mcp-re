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
//! Under the best-effort posture the order and the bytes are unchanged: G2 passes the
//! posture's statement through, and the `response.signed` record is produced when the
//! response is served, as before.

use mcp_re_http_profile::HttpResponse;

use crate::async_serve::ServedHttpResponse;
use crate::audit_record::{AuditRecord, AuditSubject};
use crate::exchange_state::{ExchangeProgress, ServedSuccess};
use crate::request_stages::{IntentDisposition, OutcomeDisposition, RetentionDisposition};

use super::super::inner_plane::NotificationDelivered;
use super::super::receipt::Accepted;
use super::super::served;
use super::super::HttpProfileProxy;

impl HttpProfileProxy {
    /// Commit the outcome, complete retention, offer the record, reach the terminal, serve.
    ///
    /// The only place a success is `served`, and it cannot be reached without the
    /// [`OutcomeDisposition`] G2 returns — under the required posture, a committed outcome.
    /// The caller has already decided `may_publish(success)`.
    pub(super) async fn publish_success(
        &self,
        acc: &Accepted<'_>,
        progress: &mut ExchangeProgress,
        success: ServedSuccess<NotificationDelivered>,
        response: HttpResponse,
        retention: &RetentionDisposition,
        intent: IntentDisposition,
    ) -> ServedHttpResponse {
        let observed = AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some(acc.exchange().actor_id.to_owned()),
            status: response.status,
            at_unix: acc.exchange().now,
        };
        // G2 BEFORE retention completes (Q2): a refusal here is what retention then holds, so
        // the retained representation stays the one actually served.
        let outcome = match self
            .audit
            .outcome(intent, acc.exchange_coordinate(), observed.clone())
            .await
        {
            Ok(outcome) => outcome,
            Err(refusal) => {
                return self
                    .refuse_retained(acc, refusal, progress, retention)
                    .await
            }
        };
        if let Some(rejection) = self
            .retain_accepted(acc, &response, retention, progress)
            .await
        {
            return rejection;
        }
        self.offer_outcome(acc, &outcome, observed);
        progress.publish(success);
        served(response)
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
    /// The success exit's order, over the source: the outcome is committed, THEN retention
    /// completes, THEN the record is offered, the terminal published and the bytes served —
    /// and each refusing arm leaves before the next step.
    ///
    /// Asserted over the source because the property is an order between statements the
    /// serving path makes, and the wrong orders are unconstructible through it.
    #[test]
    fn the_outcome_is_committed_before_retention_and_both_before_success_is_served() {
        let source = include_str!("success_exit.rs");
        let body = source
            .split_once("async fn publish_success(")
            .expect("the exit is in this file")
            .1;
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`{needle}` is in the success exit"))
        };
        let g2 = at(".outcome(intent,");
        let retention = at(".retain_accepted(");
        let offer = at("self.offer_outcome(");
        let publish = at("progress.publish(success)");
        let serve = at("served(response)");
        assert!(
            g2 < retention && retention < offer && offer < publish && publish < serve,
            "G2 {g2}, retention {retention}, offer {offer}, publish {publish}, serve {serve}"
        );
        let squeezed =
            |from: usize, to: usize| -> String { body[from..to].split_whitespace().collect() };
        assert!(
            squeezed(g2, retention).contains("Err(refusal)=>{returnself.refuse_retained("),
            "a G2 refusal must leave, discharging retention with the refusal served"
        );
        assert!(
            squeezed(retention, offer).contains("returnrejection;"),
            "a retention failure must leave before anything publishes the success"
        );
    }

    /// The success exit is the only place in the reply region that serves a success.
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
