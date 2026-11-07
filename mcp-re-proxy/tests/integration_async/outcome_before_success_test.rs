// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-070 G2 over the real serving path: under the required audit posture no success
//! is visible without the exchange's committed outcome, and nothing past the dispatch claims
//! `NothingExecuted` (D4, D7, D8, Q2).
//!
//!   signed client request
//!     → … → G1 intent committed → retention commit → dispatch      (#1204)
//!     → reply read and signed, or the 202 signed
//!     → G2: the response.signed event committed, BEFORE retention completes (Q2)
//!     → retention completes → the observer is offered the committed event → served
//!
//! The windows of §6 are forced one at a time: the outcome commit fails (W5), the outcome
//! commits and retention then fails (W5b), the request is dropped while the backend runs
//! (W4), and the response is lost after it was produced (W6). The best-effort posture is
//! pinned first: it commits nothing and serves exactly what it served before.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use mcp_re_client_proxy::ResponseKind;
use mcp_re_proxy::CollectingAuditSink;

use super::delegated_client_server_e2e_test::{
    build_server_over, plain_notification, plain_request,
};
use super::intent_before_dispatch_test::{counting_inner, deploy};

/// The best-effort posture: one `response.signed` per success at the status served, after
/// its `request.accepted`, and nothing committed — the order and records of v0.18.1.
#[test]
fn best_effort_success_and_notification_are_unchanged() {
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(CollectingAuditSink::new());
    let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
    let d = deploy(server.with_audit_sink(sink.clone()), calls, None);
    assert_eq!(d.call(&plain_request()).kind, ResponseKind::Success);
    assert_eq!(
        d.call(&plain_notification()).kind,
        ResponseKind::AcceptedNotification
    );
    let records: Vec<_> = sink
        .envelopes()
        .iter()
        .map(|e| (e.record().event().event_type(), e.record().status))
        .collect();
    assert_eq!(
        records,
        [
            ("mcp-re.request.accepted", 200),
            ("mcp-re.response.signed", 200),
            ("mcp-re.request.accepted", 200),
            ("mcp-re.response.signed", 202),
        ]
    );
    let envelopes = sink.envelopes();
    assert_eq!(
        envelopes[1].exchange_coordinate(),
        envelopes[0].exchange_coordinate()
    );
}

#[cfg(feature = "audit_commitment_reference")]
mod required_lane;

#[cfg(feature = "audit_commitment_reference")]
mod required {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::required_lane::{
        assert_possibly_executed, dropped_serving_through_a_full_observer, pending_reservations,
        possibly_executed, required, retained_statuses, serve, slow_first_backend, Posture,
        CLIENT_SKEW, SIG_TTL, UNAVAILABLE,
    };
    use super::*;
    use crate::delegated_client_server_e2e_test::params;
    use crate::intent_before_dispatch_test::required::scratch;
    use mcp_re_proxy::transparency::EvidenceRetention;
    use mcp_re_proxy::{ReferenceCommitment, ScriptedAnswer};

    /// S2: the success is served after its outcome is committed, and the committed event IS
    /// the observed `response.signed` line — distinct from the intent, one coordinate for both.
    #[test]
    fn required_success_is_visible_only_after_the_outcome_is_committed() {
        let r = required(vec![], None);
        assert_eq!(r.d.call(&plain_request()).kind, ResponseKind::Success);
        r.assert_exchange(1, 200);
        r.assert_journaled(2, "the intent, then the outcome");
        let journaled = r.reference.journaled();
        let envelopes = r.sink.envelopes();
        let (accepted, signed) = (&envelopes[0], &envelopes[1]);
        let coordinate = accepted.exchange_coordinate();
        assert_ne!(journaled[0].0, journaled[1].0, "two facts, two events");
        assert_eq!((journaled[0].1, journaled[1].1), (coordinate, coordinate));
        assert_eq!(
            signed.id(),
            journaled[1].0,
            "the observer was offered the committed event, not a second one"
        );
        assert_eq!(signed.exchange_coordinate(), coordinate);
    }

    /// W5: an outcome that cannot be committed is never served as a success. The refusal says
    /// the backend may have run, at 500, and the observer records it instead of a success.
    #[test]
    fn required_outcome_failure_never_serves_success() {
        for answer in [
            ScriptedAnswer::Reject,
            ScriptedAnswer::Unavailable,
            ScriptedAnswer::Hang,
            ScriptedAnswer::DropCompletion,
            ScriptedAnswer::PanicInPoll,
            ScriptedAnswer::ForgeReceipt,
        ] {
            let r = required(vec![ScriptedAnswer::Commit, answer], None);
            let kind = r.d.call(&plain_request()).kind;
            assert_possibly_executed(&kind, UNAVAILABLE);
            r.assert_exchange(1, 500);
            assert_eq!(
                r.reference.requests(),
                2,
                "one bounded attempt per crossing"
            );
            assert_eq!(
                r.events(),
                [
                    ("mcp-re.request.accepted", None),
                    ("mcp-re.response.rejected", Some(UNAVAILABLE)),
                ]
            );
        }
    }

    /// W5 under retention (Q2): the refusal is what retention holds, so the archive matches
    /// what was served and no crossing is left dangling.
    #[test]
    fn required_outcome_failure_discharges_retention_with_the_refusal_served() {
        let root = scratch("w5");
        let store = root.join("evidence");
        let retention = Arc::new(EvidenceRetention::open(&store).expect("open"));
        let r = required(
            vec![ScriptedAnswer::Commit, ScriptedAnswer::Unavailable],
            Some(Arc::clone(&retention)),
        );
        let kind = r.d.call(&plain_request()).kind;
        assert_possibly_executed(&kind, UNAVAILABLE);
        assert_eq!(pending_reservations(&store), Vec::<String>::new());
        assert_eq!(
            retained_statuses(&store),
            [500],
            "the retained terminal is the refusal served, never the success bytes"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// W5b (Q2): the outcome is committed and retention then fails. The client is refused —
    /// never served the success, never told nothing ran — and the committed outcome stays
    /// what it is, a fact the proxy observed, not a response the client received.
    #[test]
    fn retention_failure_after_outcome_commit_never_serves_success() {
        let root = scratch("w5b");
        let (store, moved) = (root.join("evidence"), root.join("moved"));
        let retention = Arc::new(EvidenceRetention::open(&store).expect("open"));
        let (from, to) = (store.clone(), moved.clone());
        let break_store: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            std::fs::rename(&from, &to).expect("move the store aside");
            std::fs::write(&from, b"not a directory").expect("occupy the path");
        });
        let r = required(
            vec![
                ScriptedAnswer::Commit,
                ScriptedAnswer::CommitThen(break_store),
            ],
            Some(retention),
        );
        let kind = r.d.call(&plain_request()).kind;
        assert_possibly_executed(&kind, "mcp-re.evidence_retention_indeterminate");
        r.assert_exchange(1, 500);
        r.assert_journaled(2, "intent and outcome committed");
        assert!(
            r.events()
                .iter()
                .all(|(event, _)| *event != "mcp-re.response.signed"),
            "no record of a served success: {:?}",
            r.events()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// D4: a 202 is a terminal success. Without a committed outcome there is no 202; with
    /// one, the outcome records the 202 status, and the observer is given that event.
    #[test]
    fn required_notification_gets_no_202_without_a_committed_outcome() {
        for answer in [
            ScriptedAnswer::Reject,
            ScriptedAnswer::Unavailable,
            ScriptedAnswer::Hang,
        ] {
            let r = required(vec![ScriptedAnswer::Commit, answer], None);
            let kind = r.d.call(&plain_notification()).kind;
            assert!(
                matches!(kind, ResponseKind::RejectedNotification { .. }),
                "{kind:?}"
            );
            assert_possibly_executed(&kind, UNAVAILABLE);
            r.assert_exchange(1, 500);
        }

        let r = required(vec![], None);
        assert_eq!(
            r.d.call(&plain_notification()).kind,
            ResponseKind::AcceptedNotification
        );
        let journaled = r.reference.journaled();
        let signed = &r.sink.envelopes()[1];
        assert_eq!((journaled.len(), signed.id()), (2, journaled[1].0));
        assert_eq!(
            signed.record().status,
            202,
            "acknowledgement, not completion"
        );
    }

    /// D8: a post-dispatch refusal is observed, not committed. The illegal upstream reply is
    /// refused with its own token and `possibly_executed`, exactly as before, and the
    /// authority holds the intent alone.
    #[test]
    fn signed_refusals_under_required_are_unchanged_and_commit_no_outcome() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let illegal = Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
            move |_forwarded: &[u8]| -> Vec<u8> {
                counter.fetch_add(1, Ordering::SeqCst);
                b"{\"jsonrpc\":\"2.0\",\"id\":1}".to_vec()
            },
            mcp_re_proxy::async_inner::DispatchCompletionBound::Within(Duration::ZERO),
        ));
        let (server, _) = build_server_over(illegal, 300);
        let r = serve(server, calls, vec![], Posture::default());
        let kind = r.d.call(&plain_request()).kind;
        let code = possibly_executed(&kind).expect("refused as possibly executed");
        assert_ne!(code, UNAVAILABLE, "the refusal keeps its own cause");
        assert_eq!(r.d.calls(), 1);
        r.assert_journaled(1, "the intent alone: no outcome");
    }

    /// W4: dropped while the backend runs. Nothing is invented — the authority holds the
    /// intent and no outcome — the crossing stays marked, and the proxy keeps serving.
    #[test]
    fn w4_cancel_after_dispatch_never_claims_nothing_executed() {
        let root = scratch("w4");
        let store = root.join("evidence");
        let retention = Arc::new(EvidenceRetention::open(&store).expect("open"));
        let (addr, received) = slow_first_backend(Duration::from_secs(10));
        let pool = mcp_re_proxy::http_inner::HttpInnerPool::new(
            vec![format!("http://{addr}/mcp").parse().expect("uri")],
            Duration::from_secs(5),
        )
        .expect("pool");
        let (server, _) = build_server_over(Box::new(pool), 300);
        let r = serve(
            server.with_evidence_retention(Arc::clone(&retention)),
            Arc::new(AtomicUsize::new(0)),
            vec![],
            Posture {
                // Generous: the follow-up exchange must finish inside it on a loaded runner.
                deadline: Some(Duration::from_secs(2)),
                ..Posture::default()
            },
        );
        let dropped = r.d.client.handle(
            "r1",
            &plain_request(),
            &params(&mcp_re_test_paths::unique_test_nonce()),
        );
        assert!(
            dropped.is_err(),
            "the request future was dropped mid-dispatch"
        );
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "the backend was reached"
        );
        r.assert_journaled(1, "the intent, and no outcome");
        assert_eq!(
            pending_reservations(&store).len(),
            1,
            "the crossing stays marked: possibly executed, for a reconciler"
        );
        assert_eq!(r.d.call(&plain_request()).kind, ResponseKind::Success);
        r.assert_journaled(3, "the next exchange ran in full");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// W6: the outcome was committed and the response produced, then lost before the write.
    /// The authority holds both events; delivery is not claimed by anything.
    #[test]
    fn w6_outcome_committed_then_lost_before_the_write() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
        let r = serve(
            server,
            calls,
            vec![],
            Posture {
                discard: true,
                ..Posture::default()
            },
        );
        let lost = r.d.client.handle(
            "r1",
            &plain_request(),
            &params(&mcp_re_test_paths::unique_test_nonce()),
        );
        assert!(lost.is_err(), "the client received nothing");
        r.assert_exchange(1, 200);
        r.assert_journaled(2, "intent and outcome committed");
    }

    /// O5 (ADR-MCPRE-070 §14): the response is signed before G2, so an outcome that commits
    /// only after the signature window closed is served under that closed window. The client
    /// refuses it: the backend ran and the success is lost, but no success is accepted under
    /// a lapsed signature, and the proxy neither re-signs it nor extends the window.
    ///
    /// The provider's answer moves the client's verification clock — read once, when the
    /// response arrives — to the instant G2 completed. The mirror, a G2 that completes inside
    /// the window, verifies as a success, so the refusal is the lapse and not the hook.
    #[test]
    fn a_window_that_lapses_during_g2_is_refused_by_the_client_never_accepted() {
        use std::sync::atomic::AtomicI64;

        use mcp_re_client_proxy::ProxyError;
        use mcp_re_http_profile::HttpProfileError;

        use crate::delegated_client_server_e2e_test::NOW;

        let answered_at = |at: i64, body: &serde_json::Value| {
            let clock = Arc::new(AtomicI64::new(NOW));
            let moved = Arc::clone(&clock);
            let late = ScriptedAnswer::CommitThen(Arc::new(move || {
                moved.store(at, Ordering::SeqCst);
            }));
            let calls = Arc::new(AtomicUsize::new(0));
            let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), SIG_TTL);
            let r = serve(
                server,
                calls,
                vec![ScriptedAnswer::Commit, late],
                Posture::default(),
            );
            let read = || clock.load(Ordering::SeqCst);
            let call = mcp_re_client_proxy::CallParams {
                verification_clock: &read,
                ..params(&mcp_re_test_paths::unique_test_nonce())
            };
            let verdict = r.d.client.handle("r1", body, &call);
            assert_eq!(r.d.calls(), 1, "the backend ran");
            r.assert_journaled(2, "intent and outcome committed");
            (verdict, r.d.last_status())
        };

        for (body, success, status) in [
            (plain_request(), ResponseKind::Success, 200),
            (
                plain_notification(),
                ResponseKind::AcceptedNotification,
                202,
            ),
        ] {
            let (inside, served) = answered_at(NOW + 1, &body);
            assert_eq!(served, Some(status));
            assert_eq!(inside.expect("inside the window").kind, success);

            let (lapsed, served) = answered_at(NOW + SIG_TTL + CLIENT_SKEW, &body);
            assert_eq!(served, Some(status), "the proxy served what it signed");
            let refused = lapsed.expect_err("a lapsed signature is never a success");
            assert!(
                matches!(
                    refused,
                    ProxyError::FailedClosed(HttpProfileError::StaleWindow)
                ),
                "refused for the lapse: {refused:?}"
            );
        }
    }

    /// A full observer queue changes neither dispatch nor success, in either posture: the
    /// records are dropped and counted, and under the required posture the intent and the
    /// outcome are still committed before the success is served (ADR-MCPRE-070 §7.4, §11
    /// "observer queue full").
    #[test]
    fn a_full_observer_queue_changes_neither_dispatch_nor_success() {
        assert_eq!(
            dropped_serving_through_a_full_observer(None),
            2,
            "best-effort: both dropped"
        );

        let reference = ReferenceCommitment::surviving_process_loss([]);
        assert_eq!(
            dropped_serving_through_a_full_observer(Some(&reference)),
            2,
            "required: both dropped"
        );
        assert_eq!(
            reference.journaled().len(),
            2,
            "intent and outcome committed"
        );
    }
}
