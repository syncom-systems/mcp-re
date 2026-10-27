// SPDX-License-Identifier: Apache-2.0
//! The stage after the irreversible dispatch: the notification terminal, or the reply
//! assembled, retained and served.
//!
//! Every exit from here is post-dispatch, so none of them can claim nothing happened.

use mcp_re_http_profile::OutstandingId;

use crate::async_inner::DispatchedOutcome;
use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ExchangeProgress;
use crate::request_stages::PostDispatch;

use super::super::receipt::Accepted;
use super::super::HttpProfileProxy;

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
        outcome: DispatchedOutcome,
        owed: PostDispatch,
    ) -> ServedHttpResponse {
        if outstanding.is_notification() {
            return self
                .answer_notification_terminal(acc, progress, &outcome, owed)
                .await;
        }
        let reply = match self
            .assemble_reply(acc, progress, outcome, outstanding, &owed)
            .await
        {
            Ok(reply) => reply,
            Err(rejection) => return rejection,
        };
        self.serve_retained(acc, progress, reply, owed).await
    }
}

#[cfg(test)]
mod tests {
    /// A notification never reaches the reply assembler: the terminal decision comes first,
    /// from the request, and returns.
    #[test]
    fn a_notification_is_answered_before_any_reply_is_assembled() {
        let source = include_str!("dispatched.rs");
        let body = source
            .split_once("async fn answer_dispatched(")
            .expect("the stage is in this file")
            .1;
        let notification = body
            .find("is_notification()")
            .expect("the notification decision is in the stage");
        let assemble = body
            .find(".assemble_reply(")
            .expect("the reply assembly is in the stage");
        assert!(notification < assemble);
        let between: String = body[notification..assemble].split_whitespace().collect();
        assert!(
            between.contains("returnself.answer_notification_terminal("),
            "the notification arm must return its own terminal"
        );
    }
}
