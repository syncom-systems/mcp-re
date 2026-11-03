// SPDX-License-Identifier: Apache-2.0
//! The stage after the irreversible dispatch: the notification terminal, or the reply
//! assembled, retained and served.
//!
//! Every exit from here is post-dispatch, so none of them can claim nothing happened.
//!
//! Which exit a dispatched exchange takes is decided once, from the REQUEST, by
//! [`Answering::of`]: a one-way message becomes a [`DispatchedNotification`] and a call a
//! [`DispatchedCall`]. The notification terminal takes only the first and the reply
//! assembler only the second, and their fields are private to this module, so a notification
//! has nothing to hand the assembler. "The notification is answered before any reply is
//! assembled" is the absence of a value, not the order of two statements.

use mcp_re_http_profile::OutstandingId;

use crate::async_inner::DispatchedOutcome;
use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ExchangeProgress;
use crate::request_stages::{DispatchedExchange, PostDispatch};

use super::super::receipt::Accepted;
use super::super::HttpProfileProxy;

/// A dispatched one-way message: what the notification terminal answers.
pub(super) struct DispatchedNotification {
    outcome: DispatchedOutcome,
    owed: PostDispatch,
}

impl DispatchedNotification {
    /// What the inner plane managed to do, and what the exchange still owes.
    pub(super) fn into_parts(self) -> (DispatchedOutcome, PostDispatch) {
        (self.outcome, self.owed)
    }
}

/// A dispatched call, with the id its reply must answer: what the reply assembler takes.
pub(super) struct DispatchedCall<'o> {
    outcome: DispatchedOutcome,
    answers: &'o OutstandingId,
    owed: PostDispatch,
}

impl<'o> DispatchedCall<'o> {
    /// What the inner plane managed to do, the id it answers, and what the exchange still owes.
    pub(super) fn into_parts(self) -> (DispatchedOutcome, &'o OutstandingId, PostDispatch) {
        (self.outcome, self.answers, self.owed)
    }
}

/// The two exits a dispatched exchange can take.
enum Answering<'o> {
    Notification(DispatchedNotification),
    Call(DispatchedCall<'o>),
}

impl<'o> Answering<'o> {
    /// The exit `outstanding` selects. The only producer of either dispatched value.
    fn of(exchange: DispatchedExchange, outstanding: &'o OutstandingId) -> Self {
        let (outcome, owed) = exchange.split();
        if outstanding.is_notification() {
            Self::Notification(DispatchedNotification { outcome, owed })
        } else {
            Self::Call(DispatchedCall {
                outcome,
                answers: outstanding,
                owed,
            })
        }
    }
}

impl HttpProfileProxy {
    /// Answer a dispatched exchange.
    ///
    /// NOTIFICATION — a one-way message with no JSON-RPC `id` is its own terminal: it says the
    /// boundary accepted the message, never that anything completed. Decided from the
    /// REQUEST, which is where the fact lives.
    pub(in crate::http_profile_serve) async fn answer_dispatched(
        &self,
        acc: &Accepted<'_>,
        progress: &mut ExchangeProgress,
        outstanding: &OutstandingId,
        exchange: DispatchedExchange,
    ) -> ServedHttpResponse {
        match Answering::of(exchange, outstanding) {
            Answering::Notification(message) => {
                self.answer_notification_terminal(acc, progress, message)
                    .await
            }
            Answering::Call(call) => match self.assemble_reply(acc, progress, call).await {
                Ok((reply, owed)) => self.serve_retained(acc, progress, reply, owed).await,
                Err(rejection) => rejection,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn dispatched() -> DispatchedExchange {
        crate::request_stages::test_support::dispatched_exchange(b"{\"result\":{}}").await
    }

    fn outstanding(body: &[u8]) -> OutstandingId {
        mcp_re_http_profile::validate_request_envelope(body).expect("a well-formed request")
    }

    /// A one-way message yields a notification, so there is no call for the reply assembler
    /// to take.
    #[tokio::test]
    async fn a_notification_yields_nothing_the_reply_assembler_takes() {
        let message = outstanding(br#"{"jsonrpc":"2.0","method":"notifications/x"}"#);
        assert!(matches!(
            Answering::of(dispatched().await, &message),
            Answering::Notification(_)
        ));
    }

    /// A call yields the call, carrying the id its reply must answer.
    #[tokio::test]
    async fn a_call_yields_the_call_with_the_id_it_answers() {
        let call = outstanding(br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#);
        let Answering::Call(dispatched) = Answering::of(dispatched().await, &call) else {
            panic!("a request with an id is a call");
        };
        let (outcome, answers, _owed) = dispatched.into_parts();
        assert_eq!(answers, &call);
        assert_eq!(
            outcome,
            DispatchedOutcome::Replied(b"{\"result\":{}}".to_vec())
        );
    }
}
