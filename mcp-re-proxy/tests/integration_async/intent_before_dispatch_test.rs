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
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client_core::ExecutionContract;
use mcp_re_client_proxy::ResponseKind;
use mcp_re_proxy::CollectingAuditSink;

use super::delegated_client_server_e2e_test::{
    build_server_over, params, plain_notification, plain_request,
};

mod harness;

pub(super) use harness::{counting_inner, deploy, deploy_with, Deployment, REPLY};

const INTENT: &str = "mcp-re.execution.intent";
const UNAVAILABLE: &str = "mcp-re.audit_commitment_unavailable";
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
pub(crate) mod required;
