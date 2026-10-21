// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-070 G1 over the real serving path: no backend dispatch without a committed,
//! redeemed execution intent under the required audit posture (D7, D9, D12).
//!
//!   signed client request
//!     → HttpProfileProxy::handle            (real delegated-required server)
//!     → admitted, `request.accepted` observed
//!     → forward, prepare, window, reserve
//!     → G1: intent committed to the scripted reference authority, witness redeemed
//!     → retention commit → dispatch         (counted: in-process AND a loopback HTTP backend)
//!
//! Every negative path asserts ZERO backend invocations, and that the refusal the client
//! verified states no execution hazard. The best-effort posture is pinned first: it commits
//! nothing, observes no intent, and serves exactly what it served before (D1).
//!
//! The required posture is entered through `with_required_audit_commitment`, which exists
//! only under the test-only `audit_commitment_reference` feature this lane sets.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_re_client_core::ExecutionContract;
use mcp_re_client_proxy::transport::{RemoteTransport, TransportError};
use mcp_re_client_proxy::ResponseKind;
use mcp_re_http_profile::{HttpRequest, HttpResponse};
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::{CollectingAuditSink, HttpProfileProxy};

use super::delegated_client_server_e2e_test::{
    build_server_over, client_proxy_over, params, plain_notification, plain_request, NOW,
};

const INTENT: &str = "mcp-re.execution.intent";
const UNAVAILABLE: &str = "mcp-re.audit_commitment_unavailable";
const REPLY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#;

/// An in-process backend that counts every dispatch it receives.
fn counting_inner(calls: Arc<AtomicUsize>) -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
        move |_forwarded: &[u8]| -> Vec<u8> {
            calls.fetch_add(1, Ordering::SeqCst);
            REPLY.to_vec()
        },
        mcp_re_proxy::async_inner::DispatchCompletionBound::Within(Duration::ZERO),
    ))
}

/// The network hop: drives `handle` on a private runtime, records the HTTP status it
/// served, and — when given a deadline — drops the request future at it, as a client
/// disconnect or a cancelled connection task does.
struct Hop {
    server: Arc<HttpProfileProxy>,
    rt: tokio::runtime::Runtime,
    deadline: Option<Duration>,
    statuses: Arc<Mutex<Vec<u16>>>,
}

impl RemoteTransport for Hop {
    fn round_trip(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let served = ServedHttpRequest {
            method: request.method.clone(),
            target_uri: request.target_uri.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            peer: None,
            assertion: None,
        };
        let server = Arc::clone(&self.server);
        let handled = async move { server.handle(served, NOW).await };
        let resp = match self.deadline {
            None => self.rt.block_on(handled),
            Some(d) => self
                .rt
                .block_on(async { tokio::time::timeout(d, handled).await })
                .map_err(|_| TransportError::new("the request future was dropped"))?,
        };
        self.statuses.lock().expect("statuses").push(resp.status);
        Ok(HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }
}

/// A served deployment: the client proxy, the backend counter and what the hop saw.
struct Deployment {
    client: mcp_re_client_proxy::ClientProxy,
    calls: Arc<AtomicUsize>,
    statuses: Arc<Mutex<Vec<u16>>>,
}

impl Deployment {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_status(&self) -> Option<u16> {
        self.statuses.lock().expect("statuses").last().copied()
    }

    fn call(&self, body: &serde_json::Value) -> mcp_re_client_proxy::ProxyResponse {
        self.client
            .handle("r1", body, &params(&mcp_re_test_paths::unique_test_nonce()))
            .expect("the server's answer verifies")
    }
}

fn deploy(
    server: HttpProfileProxy,
    calls: Arc<AtomicUsize>,
    deadline: Option<Duration>,
) -> Deployment {
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let hop = Hop {
        server: Arc::new(server),
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime"),
        deadline,
        statuses: Arc::clone(&statuses),
    };
    Deployment {
        client: client_proxy_over(Box::new(hop)),
        calls,
        statuses,
    }
}

/// The best-effort posture, as v0.18.1 serves it: dispatch on every admitted call,
/// `request.accepted` then `response.signed` observed per exchange, no intent anywhere,
/// and a pre-acceptance refusal that reaches no backend.
#[test]
fn best_effort_dispatch_and_refusals_are_unchanged() {
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(CollectingAuditSink::new());
    let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
    let d = deploy(server.with_audit_sink(sink.clone()), calls, None);

    let reply = d.call(&plain_request());
    assert_eq!(reply.kind, ResponseKind::Success);
    assert_eq!(
        reply.plain_response["result"]["ok"],
        serde_json::json!(true)
    );
    assert_eq!((d.calls(), d.last_status()), (1, Some(200)));

    let ack = d.call(&plain_notification());
    assert_eq!(ack.kind, ResponseKind::AcceptedNotification);
    assert_eq!((d.calls(), d.last_status()), (2, Some(202)));

    let p = params(&mcp_re_test_paths::unique_test_nonce());
    d.client.handle("r1", &plain_request(), &p).expect("first");
    let replay = d
        .client
        .handle("r1", &plain_request(), &p)
        .expect("verifies");
    assert_eq!(
        replay.kind,
        ResponseKind::VerifiedRejection {
            wire_code: Some("mcp-re.replay_detected".into()),
            bound: true,
            execution: ExecutionContract::default(),
        }
    );
    assert_eq!(d.calls(), 3, "the replay reached no backend");

    let events: Vec<&str> = sink
        .records()
        .iter()
        .map(|r| r.event().event_type())
        .collect();
    assert_eq!(
        events,
        [
            "mcp-re.request.accepted",
            "mcp-re.response.signed",
            "mcp-re.request.accepted",
            "mcp-re.response.signed",
            "mcp-re.request.accepted",
            "mcp-re.response.signed",
            "mcp-re.request.rejected",
        ]
    );
    assert!(
        !events.contains(&INTENT),
        "the best-effort stream emits no intent (D1)"
    );
}

#[cfg(feature = "audit_commitment_reference")]
mod required {
    use super::*;
    use mcp_re_proxy::{ReferenceCommitment, ScriptedAnswer};

    const BOUND: Duration = Duration::from_millis(250);

    fn required(
        reference: &ReferenceCommitment,
        bound: Duration,
    ) -> (Deployment, Arc<CollectingAuditSink>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CollectingAuditSink::new());
        let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
        let server = server
            .with_audit_sink(sink.clone())
            .with_required_audit_commitment(reference, bound)
            .expect("an eligible reference and a legal bound");
        (deploy(server, calls, None), sink)
    }

    fn refused_unavailable() -> ResponseKind {
        ResponseKind::VerifiedRejection {
            wire_code: Some(UNAVAILABLE.into()),
            bound: true,
            execution: ExecutionContract::default(),
        }
    }

    /// The positive path: the intent is journaled BEFORE the backend runs, it names the
    /// exchange its `request.accepted` opened (D9), it lies between that event and the
    /// signed response in the run, and the observer never sees it (D1).
    #[test]
    fn required_commit_dispatches_once_after_the_intent_is_journaled() {
        let reference = ReferenceCommitment::surviving_process_loss([ScriptedAnswer::Commit]);
        let (d, sink) = required(&reference, BOUND);
        assert_eq!(d.call(&plain_request()).kind, ResponseKind::Success);
        assert_eq!((d.calls(), d.last_status()), (1, Some(200)));

        let journaled = reference.journaled();
        assert_eq!(journaled.len(), 1, "one intent per dispatched exchange");
        let envelopes = sink.envelopes();
        assert_eq!(
            envelopes.len(),
            2,
            "accepted and signed only: no intent is observed"
        );
        let (accepted, signed) = (&envelopes[0], &envelopes[1]);
        assert_eq!(journaled[0].1, accepted.exchange_coordinate());
        let run = accepted.id().run();
        let seq = |id: mcp_re_proxy::audit_record::EventId| id.seq_within(&run);
        assert!(seq(accepted.id()) < seq(journaled[0].0));
        assert!(seq(journaled[0].0) < seq(signed.id()));
        assert!(envelopes
            .iter()
            .all(|e| e.record().event().event_type() != INTENT && e.id() != journaled[0].0));
    }

    /// Absent, failed, delayed and mismatched commitment: each one is a signed refusal the
    /// client verifies, with the new token, the status that says whether a retry here can
    /// succeed, no execution hazard stated, and ZERO backend invocations.
    #[test]
    fn required_failures_reach_no_backend() {
        let cases = [
            (ScriptedAnswer::Unavailable, 503),
            (ScriptedAnswer::Reject, 500),
            (ScriptedAnswer::Hang, 503),
            (ScriptedAnswer::DropCompletion, 503),
            (ScriptedAnswer::PanicInPoll, 503),
            (ScriptedAnswer::PanicBeforeFuture, 503),
            (ScriptedAnswer::ForgeReceipt, 503),
            (ScriptedAnswer::ForgeTier, 503),
        ];
        for (answer, status) in cases {
            let reference = ReferenceCommitment::surviving_process_loss([answer]);
            let (d, sink) = required(&reference, Duration::from_millis(50));
            assert_eq!(d.call(&plain_request()).kind, refused_unavailable());
            assert_eq!(d.last_status(), Some(status));
            assert_eq!(
                d.calls(),
                0,
                "no backend invocation without a committed intent"
            );
            assert_eq!(
                reference.requests(),
                1,
                "one bounded attempt, no retry loop"
            );
            let events: Vec<_> = sink
                .records()
                .iter()
                .map(|r| (r.event().event_type(), r.event().reason()))
                .collect();
            assert_eq!(
                events,
                [
                    ("mcp-re.request.accepted", None),
                    ("mcp-re.response.rejected", Some(UNAVAILABLE)),
                ]
            );
        }
    }

    /// A receipt for the PREVIOUS exchange's intent does not admit this one.
    #[test]
    fn a_stale_receipt_reaches_no_backend() {
        let reference = ReferenceCommitment::surviving_process_loss([
            ScriptedAnswer::Commit,
            ScriptedAnswer::ReplayPrevious,
        ]);
        let (d, _) = required(&reference, BOUND);
        assert_eq!(d.call(&plain_request()).kind, ResponseKind::Success);
        assert_eq!(d.call(&plain_request()).kind, refused_unavailable());
        assert_eq!(d.calls(), 1, "only the committed exchange ran");
    }

    /// Notifications dispatch through the same ready state: without a committed intent there
    /// is no 202 and no backend call; with one, the 202 follows the journaled intent.
    #[test]
    fn required_notification_without_commitment_gets_no_202() {
        let reference = ReferenceCommitment::surviving_process_loss([ScriptedAnswer::Unavailable]);
        let (d, _) = required(&reference, BOUND);
        assert_eq!(
            d.call(&plain_notification()).kind,
            ResponseKind::RejectedNotification {
                wire_code: Some(UNAVAILABLE.into()),
                bound: true,
                execution: ExecutionContract::default(),
            }
        );
        assert_eq!((d.calls(), d.last_status()), (0, Some(503)));

        let committing = ReferenceCommitment::surviving_process_loss([ScriptedAnswer::Commit]);
        let (d, _) = required(&committing, BOUND);
        assert_eq!(
            d.call(&plain_notification()).kind,
            ResponseKind::AcceptedNotification
        );
        assert_eq!((d.calls(), committing.journaled().len()), (1, 1));
    }

    fn cancelled(answer: ScriptedAnswer) -> (Deployment, ReferenceCommitment) {
        let reference = ReferenceCommitment::surviving_process_loss([answer]);
        let calls = Arc::new(AtomicUsize::new(0));
        let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
        let server = server
            .with_required_audit_commitment(&reference, Duration::from_secs(10))
            .expect("eligible");
        let d = deploy(server, calls, Some(Duration::from_millis(100)));
        let dropped = d.client.handle(
            "r1",
            &plain_request(),
            &params(&mcp_re_test_paths::unique_test_nonce()),
        );
        assert!(
            dropped.is_err(),
            "the request future was dropped mid-commit"
        );
        (d, reference)
    }

    /// W2, dropped while the provider has not answered: nothing is dispatched, at once or
    /// after a grace period — the dispatch lived in the dropped future.
    #[test]
    fn cancelled_during_intent_commit_reaches_no_backend() {
        let (d, reference) = cancelled(ScriptedAnswer::Hang);
        assert_eq!(d.calls(), 0);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(d.calls(), 0, "nothing was left running to dispatch later");
        assert_eq!(reference.requests(), 1);
        assert!(reference.journaled().is_empty());
    }

    /// W2's honest reading: the store may hold the intent the proxy never heard back about,
    /// so a reconciler reads PossiblyExecuted as an upper bound — and the proxy itself knows
    /// nothing ran.
    #[test]
    fn crash_window_w2_store_may_hold_intent_but_nothing_ran() {
        let (d, reference) = cancelled(ScriptedAnswer::CommitThenPark);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(d.calls(), 0);
        assert_eq!(reference.journaled().len(), 1, "the intent is in the store");
    }

    fn files_under(dir: &std::path::Path, suffix: &str) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.to_string_lossy().ends_with(suffix) {
                    found.push(path);
                }
            }
        }
        found
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-re-intent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// W3: the intent commits, then the retention crossing cannot be recorded. The live
    /// process refuses with NothingExecuted, nothing runs, and no `.pending` marker exists —
    /// so on disk, too, nothing says the threshold was crossed.
    #[test]
    fn w3_retention_commit_failure_after_intent_leaves_no_pending_and_no_dispatch() {
        let root = scratch("w3");
        let (evidence, moved) = (root.join("evidence"), root.join("moved"));
        let retention =
            Arc::new(mcp_re_proxy::transparency::EvidenceRetention::open(&evidence).expect("open"));
        let (from, to) = (evidence.clone(), moved.clone());
        let break_store: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            std::fs::rename(&from, &to).expect("move the store aside");
            std::fs::write(&from, b"not a directory").expect("occupy the path");
        });
        let reference =
            ReferenceCommitment::surviving_process_loss([ScriptedAnswer::CommitThen(break_store)]);
        let calls = Arc::new(AtomicUsize::new(0));
        let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
        let server = server
            .with_evidence_retention(retention)
            .with_required_audit_commitment(&reference, BOUND)
            .expect("eligible");
        let d = deploy(server, calls, None);

        let refused = d.call(&plain_request());
        let ResponseKind::VerifiedRejection {
            wire_code,
            execution,
            ..
        } = refused.kind
        else {
            panic!("refused, not served: {:?}", refused.kind);
        };
        assert_eq!(
            wire_code.as_deref(),
            Some("mcp-re.evidence_retention_unavailable")
        );
        assert_ne!(
            execution.execution(),
            mcp_re_client_core::ExecutionStatus::PossiblyExecuted
        );
        assert_eq!(d.calls(), 0);
        assert_eq!(
            reference.journaled().len(),
            1,
            "the intent was committed first (D7)"
        );
        assert!(
            files_under(&moved, ".pending").is_empty(),
            "no crossing was recorded"
        );
        assert!(
            !files_under(&moved, ".reserved").is_empty(),
            "the reserve ran before G1"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A G1 failure after the reserve rescinds the reservation: the store is left with
    /// neither marker once its writer has drained.
    #[test]
    fn g1_failure_rescinds_the_reservation() {
        let root = scratch("rescind");
        let evidence = root.join("evidence");
        let retention =
            Arc::new(mcp_re_proxy::transparency::EvidenceRetention::open(&evidence).expect("open"));
        let reference = ReferenceCommitment::surviving_process_loss([ScriptedAnswer::Unavailable]);
        let calls = Arc::new(AtomicUsize::new(0));
        let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
        let server = server
            .with_evidence_retention(retention)
            .with_required_audit_commitment(&reference, BOUND)
            .expect("eligible");
        let d = deploy(server, calls, None);
        assert_eq!(d.call(&plain_request()).kind, refused_unavailable());
        assert_eq!(d.calls(), 0);
        let mut waited = Duration::ZERO;
        while !files_under(&evidence, ".reserved").is_empty() && waited < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
            waited += Duration::from_millis(20);
        }
        assert!(
            files_under(&evidence, ".reserved").is_empty(),
            "the reservation was rescinded"
        );
        assert!(files_under(&evidence, ".pending").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The signing window must survive the intent's bounded wait as well as the dispatch:
    /// a window that covers only the dispatch is refused BEFORE the reserve and before any
    /// intent is produced, where refusing is free; one that covers both serves.
    #[test]
    fn the_window_must_survive_the_commitment_wait() {
        let serve_with = |bound: Duration| {
            let reference = ReferenceCommitment::surviving_process_loss([]);
            let calls = Arc::new(AtomicUsize::new(0));
            let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 20);
            let server = server
                .with_required_audit_commitment(&reference, bound)
                .expect("eligible");
            let d = deploy(server, calls, None);
            (
                d.call(&plain_request()).kind,
                d.calls(),
                reference.requests(),
            )
        };
        let (kind, calls, asked) = serve_with(Duration::from_secs(30));
        assert_eq!(
            kind,
            ResponseKind::VerifiedRejection {
                wire_code: Some("mcp-re.delegated_signing_unavailable".into()),
                bound: true,
                execution: ExecutionContract::default(),
            }
        );
        assert_eq!(
            (calls, asked),
            (0, 0),
            "refused before any intent was produced"
        );
        let (kind, calls, asked) = serve_with(Duration::from_secs(10));
        assert_eq!((kind, calls, asked), (ResponseKind::Success, 1, 1));
    }

    /// D3 and the bound hold at the installer: not even a test serves the required posture
    /// over a volatile authority or a wait the request could not survive.
    #[test]
    fn the_installer_refuses_a_volatile_authority_and_an_illegal_bound() {
        let build = || build_server_over(counting_inner(Arc::new(AtomicUsize::new(0))), 300).0;
        assert!(build()
            .with_required_audit_commitment(&ReferenceCommitment::process_volatile(), BOUND)
            .is_err());
        let eligible = ReferenceCommitment::surviving_process_loss([]);
        assert!(build()
            .with_required_audit_commitment(&eligible, Duration::ZERO)
            .is_err());
        assert!(build()
            .with_required_audit_commitment(&eligible, Duration::from_secs(3600))
            .is_err());
    }

    /// Over a real loopback HTTP backend: the committed exchange reaches it once, and the
    /// refused one never opens a request to it.
    #[test]
    fn required_over_a_loopback_http_backend_dispatches_only_after_commit() {
        use http_body_util::Full;
        use hyper_util::rt::{TokioExecutor, TokioIo};

        let backend = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("backend runtime");
        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let addr = backend.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let counter = Arc::clone(&counter);
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |_req| {
                            counter.fetch_add(1, Ordering::SeqCst);
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "application/json")
                                        .body(Full::new(bytes::Bytes::from_static(REPLY)))
                                        .expect("response"),
                                )
                            }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
            addr
        });
        let pool = |_: ()| -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
            Box::new(
                mcp_re_proxy::http_inner::HttpInnerPool::new(
                    vec![format!("http://{addr}/mcp").parse().expect("uri")],
                    Duration::from_secs(5),
                )
                .expect("pool"),
            )
        };
        for (answer, expected, received_after) in [
            (ScriptedAnswer::Unavailable, refused_unavailable(), 0),
            (ScriptedAnswer::Commit, ResponseKind::Success, 1),
        ] {
            let reference = ReferenceCommitment::surviving_process_loss([answer]);
            let (server, _) = build_server_over(pool(()), 300);
            let server = server
                .with_required_audit_commitment(&reference, BOUND)
                .expect("eligible");
            let d = deploy(server, Arc::new(AtomicUsize::new(0)), None);
            assert_eq!(d.call(&plain_request()).kind, expected);
            assert_eq!(received.load(Ordering::SeqCst), received_after);
        }
    }
}
