// SPDX-License-Identifier: Apache-2.0
//! Notifications: a 202 only for a notification the inner plane delivered.

use super::*;

/// **R8-C047 / C050 / C051 / C081 / C083.** A notification the inner plane did not deliver
/// is not acknowledged with a signed 202.
///
/// Broken implementation this must catch: branch to `answer_notification` before
/// `observe_inner_stage` and drop the `DispatchedOutcome` unread. Every outcome then
/// collapses into one delegated-signed bodyless 202 that the client verifies and, per the
/// SDK contract, treats as the signal to stop — so a `notifications/cancelled` whose answer
/// never came is indistinguishable from one the backend received, under a signature from
/// the enforcement boundary. Because `observe_origin` was never called on that arm, the
/// machine's own guard against serving synthesized transport-failure bytes as a success
/// could not fire either.
///
/// RB-09's split is asserted per outcome. The *nothing was transmitted* half is no longer
/// among them: since #741 it is decided before the exchange commits to a dispatch, by the
/// refusing inner plane, and there is no post-commitment outcome that can claim it.
/// What remains here is the harder case — transmitted with no answer is 504, and the 504
/// states that the message may have been acted on.
#[tokio::test]
async fn a_notification_the_inner_plane_never_delivered_is_not_acknowledged() {
    let timed_out = notification_proxy(DispatchedOutcome::Indeterminate("inner request timed out"));
    let served = serve_notification(&timed_out).await;
    assert_refused(
        &served,
        Refusal {
            status: 504,
            code: INDETERMINATE,
            why: "an undelivered notification is not a 202",
        },
    );
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "a notification transmitted with no answer may have been acted on",
    );
}

/// The other half of the split, and the non-vacuity control for it: a notification the
/// backend RECEIVED is still acknowledged with a bodyless 202.
///
/// Both accepting outcomes are exercised, and `InvalidUpstream` is the load-bearing one.
/// A conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
/// body — no `application/json` content type — which the inner client classifies as an
/// unusable answer from a backend that nevertheless received the message. Refusing it
/// would break every conformant notification, so the split is on delivery, not on
/// whether the reply was usable.
#[tokio::test]
async fn a_delivered_notification_is_still_acknowledged_with_a_202() {
    let replied = notification_proxy(DispatchedOutcome::Replied(Vec::new()));
    let served = serve_notification(&replied).await;
    assert_status(&served, 202, "the backend received the message");
    assert!(served.body.is_empty(), "the 202 is bodyless");

    let bodyless_202 = notification_proxy(DispatchedOutcome::InvalidUpstream(
        "inner backend did not answer application/json",
    ));
    let served2 = serve_notification(&bodyless_202).await;
    assert_status(
        &served2,
        202,
        "a backend that answered 202-no-body received the notification",
    );
}
