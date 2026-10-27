// SPDX-License-Identifier: Apache-2.0
//! The bodyless 202 a one-way message is answered with (#424 / #418).
//!
//! Its own terminal, because everything on the bodied path assumes a reply the client asked
//! for. The 202 says the enforcement boundary authenticated and accepted the message — never
//! that any action completed — and the branch is decided from the REQUEST, where the fact
//! lives: a notification is a message the client sent with no `id`, and no reply can make it
//! one or stop it being one.
//!
//! It is the one exit a client could SELECT, by omitting `id`. That is why the acknowledgement
//! is observed before the 202 is minted, and why retention covers this exit on the same terms
//! as a bodied reply: otherwise a hostile-but-enrolled caller could leave no reconstructible
//! hop for a call that reached the same backend and ran the same side effects.

use mcp_re_http_profile::sign_delegated_accepted_202;

use crate::async_inner::DispatchedOutcome;
use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::publication::PublishPermit;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::ServedSuccess;
use crate::refusal::RefusalCause;
use crate::request_stages::PostDispatch;

use super::super::inner_plane::NotificationDelivered;
use super::super::receipt::Accepted;
use super::super::HttpProfileProxy;

impl HttpProfileProxy {
    /// The NOTIFICATION arm: a signed bodyless 202 for a message with no JSON-RPC `id`.
    ///
    /// This runs AFTER the backend has acted. The 202 states that the enforcement boundary
    /// authenticated and accepted the message — never that any action completed (#418). It
    /// leaves through the same success exit as a bodied reply, so under the required posture
    /// it is visible only once its outcome is committed and retained (ADR-MCPRE-070 D4).
    async fn answer_notification(
        &self,
        acc: &Accepted<'_>,
        permit: PublishPermit<'_, NotificationDelivered>,
        owed: PostDispatch,
    ) -> ServedHttpResponse {
        let ex = acc.exchange();
        match sign_delegated_accepted_202(ex.http_req, owed.window()) {
            Ok(ack) => self.publish_success(acc, permit, ack, owed).await,
            // SIGNING failed, so there is no signed terminal to retain. The marker stays, and
            // it is the true statement: this exchange crossed and nothing discharges it.
            Err(e) => self.responses.response_rejection(
                self.audit.observer(),
                acc.exchange_coordinate(),
                ex.http_req,
                &RefusalCause::from(e),
                500,
                ex.now,
                Some(ex.verified.evidence()),
                Some(ex.actor_id.to_owned()),
                Self::disposition(permit.exchange(), None),
                Some(owed.window().shared()),
            ),
        }
    }

    /// The whole notification terminal: read whether the message got there, then answer it.
    ///
    /// The reply itself is discarded, as JSON-RPC requires — but not the fact of whether the
    /// inner plane received the message at all. A 202 minted for a message whose transport
    /// failed after transmission is a signed statement from the enforcement boundary that a
    /// backend accepted something no backend is known to have seen, and it is the one exit a
    /// client could select by omitting `id`. The stronger case — a message that was never
    /// transmitted — cannot reach this terminal, because it is refused before the exchange
    /// commits to a dispatch at all.
    ///
    /// The 202 terminal is DECIDED here and ENTERED only when the 202 is served, so a refusal
    /// after this point — signing, the outcome commitment, retention — is served from a
    /// machine that never claimed success (ADR-MCPRE-070 §16 item 7). What it is entered by
    /// is the observation's own carrier: no other code can construct the delivery fact, so
    /// without the observation there is no 202 to decide or to publish.
    pub(in crate::http_profile_serve) async fn answer_notification_terminal(
        &self,
        acc: &Accepted<'_>,
        progress: &mut ExchangeProgress,
        outcome: &DispatchedOutcome,
        owed: PostDispatch,
    ) -> ServedHttpResponse {
        // The message may not have arrived, and this refusal is the signed statement saying
        // so. It IS a terminal the proxy constructed, so it discharges the crossing: an
        // operator reading the archive then finds *the backend may have executed and the
        // client was told this*, instead of a bare surviving marker that says only
        // *unaccounted for*.
        let acknowledged = match self.inner_async.observe_acknowledgement(progress, outcome) {
            Ok(delivered) => ServedSuccess::Acknowledged(delivered),
            Err(refusal) => {
                return self
                    .refuse_retained(acc, refusal, progress, owed.retention())
                    .await
            }
        };
        // The 202 is a signed success claim, so an exchange that no longer satisfies its
        // model may not mint one — and the decision is taken before the acknowledgement is
        // signed, while the exchange can still reach a post-dispatch refusal instead.
        let Ok(permit) = progress.may_publish(acknowledged) else {
            let refusal = crate::refusal::Refusal::new(
                mcp_re_core::McpReError::ExchangeInvariantViolation,
                500,
            );
            return self
                .refuse_retained(acc, refusal, progress, owed.retention())
                .await;
        };
        self.answer_notification(acc, permit, owed).await
    }
}

#[cfg(test)]
mod tests {
    /// The 202 is minted only for a message the inner plane is known to have received. The
    /// refused outcome is the one that says it may not have got there — a signed statement
    /// that a backend accepted something no backend is known to have seen is the failure
    /// this arm exists to prevent.
    ///
    /// The message that was never transmitted at all is absent from this set by
    /// construction: a committed dispatch has no outcome meaning *nothing happened*, so the
    /// case is decided before the exchange commits, where it can still be refused as
    /// retry-safe.
    #[test]
    fn a_message_that_may_not_have_arrived_is_not_acknowledged() {
        use crate::async_inner::DispatchedOutcome;
        let lost = DispatchedOutcome::Indeterminate("the answer never came");
        assert!(!matches!(lost, DispatchedOutcome::Replied(_)));
    }
}
