// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! The deployment the required-posture cases run against, and the readings they take of it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client_core::ExecutionStatus;
use mcp_re_client_proxy::ResponseKind;
use mcp_re_proxy::transparency::{EvidenceRetention, RetainedArchive};
use mcp_re_proxy::{CollectingAuditSink, HttpProfileProxy, ReferenceCommitment, ScriptedAnswer};

use crate::delegated_client_server_e2e_test::{build_server_over, plain_request};
use crate::intent_before_dispatch_test::required::files_under;
use crate::intent_before_dispatch_test::{counting_inner, deploy, deploy_with, Deployment, REPLY};

pub(super) const UNAVAILABLE: &str = "mcp-re.audit_commitment_unavailable";
const BOUND: Duration = Duration::from_millis(50);

/// A response signature window shorter than the delegated credential's remaining life, so
/// the window lapses first and is the only thing that has.
pub(super) const SIG_TTL: i64 = 120;

/// The clock skew the client's route tolerates (`client_proxy_over`): a verifier admits a
/// response until `expires + CLIENT_SKEW`, so that is the first instant it has lapsed.
pub(super) const CLIENT_SKEW: i64 = 60;

/// The wire code a refusal carries, when — and only when — it says the backend may have run.
pub(super) fn possibly_executed(kind: &ResponseKind) -> Option<String> {
    let (wire_code, execution) = match kind {
        ResponseKind::VerifiedRejection {
            wire_code,
            execution,
            ..
        }
        | ResponseKind::RejectedNotification {
            wire_code,
            execution,
            ..
        } => (wire_code, execution),
        _ => return None,
    };
    (execution.execution() == ExecutionStatus::PossiblyExecuted)
        .then(|| wire_code.clone().unwrap_or_default())
}

/// `kind` is a refusal saying the backend may have run, with `code` as its cause.
pub(super) fn assert_possibly_executed(kind: &ResponseKind, code: &str) {
    assert_eq!(possibly_executed(kind).as_deref(), Some(code), "{kind:?}");
}

/// A deployment serving under the required audit posture, with the sink and the commitment
/// authority its records and journal can be read back from.
pub(super) struct Required {
    pub(super) d: Deployment,
    pub(super) sink: Arc<CollectingAuditSink>,
    pub(super) reference: ReferenceCommitment,
}

/// How the deployment's client side behaves.
#[derive(Default)]
pub(super) struct Posture {
    pub(super) deadline: Option<Duration>,
    pub(super) discard: bool,
}

pub(super) fn serve(
    server: HttpProfileProxy,
    calls: Arc<AtomicUsize>,
    script: Vec<ScriptedAnswer>,
    posture: Posture,
) -> Required {
    let reference = ReferenceCommitment::surviving_process_loss(script);
    let sink = Arc::new(CollectingAuditSink::new());
    let server = server
        .with_audit_sink(sink.clone())
        .with_required_audit_commitment(&reference, BOUND)
        .expect("an eligible reference and a legal bound");
    Required {
        d: deploy_with(server, calls, posture.deadline, posture.discard),
        sink,
        reference,
    }
}

pub(super) fn required(
    script: Vec<ScriptedAnswer>,
    retention: Option<Arc<EvidenceRetention>>,
) -> Required {
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
    if let Some(retention) = retention {
        server = server.with_evidence_retention(retention);
    }
    serve(server, calls, script, Posture::default())
}

impl Required {
    pub(super) fn events(&self) -> Vec<(&'static str, Option<&'static str>)> {
        self.sink
            .records()
            .iter()
            .map(|r| (r.event().event_type(), r.event().reason()))
            .collect()
    }

    /// The backend was reached `calls` times and the last response went out at `status`.
    pub(super) fn assert_exchange(&self, calls: usize, status: u16) {
        assert_eq!(
            (self.d.calls(), self.d.last_status()),
            (calls, Some(status))
        );
    }

    /// The authority journaled exactly `count` events.
    pub(super) fn assert_journaled(&self, count: usize, why: &str) {
        assert_eq!(self.reference.journaled().len(), count, "{why}");
    }
}

/// The statuses of every retained response, read from the store's records.
pub(super) fn retained_statuses(store: &std::path::Path) -> Vec<u64> {
    files_under(store, "")
        .into_iter()
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter_map(|record| record["response"]["status"].as_u64())
        .collect()
}

/// The reservations the archive at `store` still lists as pending.
pub(super) fn pending_reservations(store: &std::path::Path) -> Vec<String> {
    RetainedArchive::open_read_only(store)
        .expect("open the archive")
        .pending_reservations()
        .expect("list")
}

/// An observer whose queue is full: every record it is offered is dropped and counted,
/// as the stderr sink does past its ceiling.
#[derive(Default)]
pub(super) struct FullObserver {
    pub(super) dropped: AtomicUsize,
}

impl mcp_re_proxy::AuditSink for FullObserver {
    fn record(&self, _envelope: &mcp_re_proxy::audit_record::AuditEnvelope) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }

    fn unnumbered(&self, _failure: &mcp_re_proxy::audit_record::EventIdentityFailure) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// One request served through a full observer, under the best-effort posture or — given a
/// commitment authority — the required one. Returns how many records the observer dropped.
pub(super) fn dropped_serving_through_a_full_observer(
    reference: Option<&ReferenceCommitment>,
) -> usize {
    let calls = Arc::new(AtomicUsize::new(0));
    let full = Arc::new(FullObserver::default());
    let (server, _) = build_server_over(counting_inner(Arc::clone(&calls)), 300);
    let mut server = server.with_audit_sink(full.clone());
    if let Some(reference) = reference {
        server = server
            .with_required_audit_commitment(reference, BOUND)
            .expect("an eligible reference and a legal bound");
    }
    let d = deploy(server, calls, None);
    assert_eq!(d.call(&plain_request()).kind, ResponseKind::Success);
    assert_eq!((d.calls(), d.last_status()), (1, Some(200)));
    full.dropped.load(Ordering::SeqCst)
}

/// A loopback HTTP backend that answers its first request only after `delay`, and every
/// later one at once.
pub(super) fn slow_first_backend(delay: Duration) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("backend runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("addr")).expect("send");
            while let Ok((stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |_req| {
                        let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
                        async move {
                            if first {
                                tokio::time::sleep(delay).await;
                            }
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
    });
    (rx.recv().expect("the backend is listening"), received)
}
