// SPDX-License-Identifier: Apache-2.0
//! What the serving path keeps, and what it refuses, around the retention store.

use super::fixtures::{Scratch, TARGET};
use super::server::{
    build_server, build_server_breaking_store_on_dispatch, build_server_counting,
    build_server_refusing, serve_one, serve_one_full, serve_one_notification,
};
use mcp_re_proxy::transparency::EvidenceRetention;
use mcp_re_test_paths::unique_test_nonce;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The store directory goes away and a regular file takes its name, so every write under
/// it fails at the filesystem — the closest thing to a full or unmounted volume that a
/// hermetic test can arrange.
fn replace_store_with_a_file(evidence: &std::path::Path) {
    std::fs::remove_dir_all(evidence).expect("remove the store directory");
    std::fs::write(evidence, b"not a directory").expect("occupy the path");
}

fn retention_unavailable() -> (u16, Option<String>) {
    (
        503,
        Some("mcp-re.evidence_retention_unavailable".to_owned()),
    )
}

/// R7-C010/C011/C012/C019/C034: retention must not be a message class the CLIENT picks.
///
/// A notification reaches the same backend and runs the same side effects as a bodied
/// call; it is merely answered with a signed bodyless 202 instead of a body. When the
/// retention hook sat only on the bodied exit, dropping the JSON-RPC `id` served the
/// call, ran it, emitted `response.signed` — and retained nothing, so no receipt could
/// ever be issued about it.
#[test]
fn a_served_notification_is_retained_like_any_other_accepted_exchange() {
    let scratch = Scratch::new("notification-retained");
    let proxy = build_server(Some(scratch.retention()));

    assert_eq!(
        serve_one_notification(&proxy, &unique_test_nonce()),
        202,
        "a one-way notification is acknowledged with a signed bodyless 202"
    );

    assert_eq!(
        scratch.retained_names().len(),
        1,
        "the accepted notification must be retained; omitting the JSON-RPC id must not \
         be a way to have a served, executed call leave no reconstructible hop"
    );
}

/// **R11-461, the hostile control.** A caller that can produce a post-dispatch refusal on
/// demand must not be able to accumulate `.pending` crossings.
///
/// An unrecognised `resultType` is refused AFTER the dispatch — the backend ran, and MCP
/// 2026-07-28 requires the unrecognised one be rejected. When the retention hook sat only on
/// the success exits, every such exchange left a `DispatchCommitted` marker with no
/// completion record. An operator reconciling then read thousands of *indeterminate*
/// crossings that were in fact ordinary refusals, which is the signal the marker exists to
/// carry being drowned by the cheapest thing a caller can do.
///
/// The invariant: a `.pending` marker means *this request crossed the execution threshold
/// AND no durable retained terminal exchange discharges that responsibility.* The proxy
/// holds the exact signed refusal it is about to serve, so it can discharge it — and the
/// archive then records what happened instead of saying only *unaccounted for*.
#[test]
fn a_post_dispatch_refusal_leaves_no_dangling_crossing() {
    let scratch = Scratch::new("refusal-retained");
    let dispatches = Arc::new(AtomicUsize::new(0));
    let proxy = build_server_refusing(Some(scratch.retention()), Arc::clone(&dispatches));

    let status = serve_one(&proxy, &unique_test_nonce());
    assert_ne!(status, 200, "an unrecognised resultType is refused");
    assert_eq!(
        dispatches.load(Ordering::SeqCst),
        1,
        "the refusal is POST-dispatch: the backend ran, which is what makes the crossing \
         real"
    );

    assert_eq!(
        scratch.archive().pending_reservations().expect("list"),
        Vec::<String>::new(),
        "the refusal is a terminal the proxy constructed and retained, so the crossing is \
         discharged; a surviving marker here would say the exchange is unaccounted for when \
         the archive holds exactly what happened"
    );
    let retained: Vec<_> = scratch
        .retained_names()
        .into_iter()
        .filter(|name| !name.ends_with(".pending"))
        .collect();
    assert_eq!(
        retained.len(),
        1,
        "the served refusal IS the terminal hop, and the archive records it"
    );
}

/// **The mirror.** A deployment with retention OFF still serves the same refusal.
///
/// Without it the control above passes against a proxy that refuses to serve anything it
/// cannot retain — which would turn every unretainable refusal into a different refusal and
/// lose the cause the client needs.
#[test]
fn a_post_dispatch_refusal_is_served_the_same_where_nothing_is_retained() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let with_store = Scratch::new("refusal-mirror");
    let retained_status = serve_one(
        &build_server_refusing(Some(with_store.retention()), Arc::clone(&dispatches)),
        &unique_test_nonce(),
    );

    let bare_status = serve_one(
        &build_server_refusing(None, Arc::clone(&dispatches)),
        &unique_test_nonce(),
    );

    assert_eq!(
        retained_status, bare_status,
        "retention changes what the ARCHIVE holds, never what the client is told"
    );
    assert_eq!(
        dispatches.load(Ordering::SeqCst),
        2,
        "both exchanges crossed the threshold"
    );
}

/// Retention is off unless a deployment turns it on, and off means the request path is
/// unchanged — no store, no directory, nothing kept.
#[test]
fn retention_is_off_by_default_and_nothing_is_kept() {
    let scratch = Scratch::new("off");
    let proxy = build_server(None);
    assert_eq!(serve_one(&proxy, &unique_test_nonce()), 200);
    assert!(
        !scratch.join("evidence").exists(),
        "a deployment that did not ask for retention stores nothing"
    );
}

/// A deployment with retention ON is asserting it can account for what it served, so an
/// exchange whose evidence cannot be kept is REFUSED rather than served silently.
///
/// The failure is injected by replacing the store directory with a regular file.
#[test]
fn an_exchange_whose_evidence_cannot_be_retained_is_refused() {
    let scratch = Scratch::new("failclosed");
    let proxy = build_server(Some(scratch.retention()));

    // The store opened; now the directory goes away and a file takes its name.
    replace_store_with_a_file(&scratch.join("evidence"));

    // The REASON, not just the status: 503 is also what an unavailable replay tier
    // returns, and a test that accepted any 503 here would keep passing if retention
    // stopped running altogether and something else refused the call.
    assert_eq!(
        serve_one_full(&proxy, &unique_test_nonce()),
        retention_unavailable(),
        "serving a call the deployment cannot account for would break the assertion \
         turning retention on makes"
    );
}

/// R7-C018/C045/C058: a known-unwritable store must stop the call BEFORE the backend.
///
/// 503 says "nothing happened, retry is safe", and that is only true if the refusal
/// happened on the near side of the execution boundary. Asserting the status alone
/// cannot tell the two sides apart, so this counts inner dispatches: the honest 503
/// requires the backend to have run zero times.
#[test]
fn a_retention_store_that_cannot_accept_the_call_refuses_before_the_backend_runs() {
    let scratch = Scratch::new("prereserve");
    let dispatches = Arc::new(AtomicUsize::new(0));
    let proxy = build_server_counting(Some(scratch.retention()), Arc::clone(&dispatches));

    replace_store_with_a_file(&scratch.join("evidence"));

    assert_eq!(
        serve_one_full(&proxy, &unique_test_nonce()),
        retention_unavailable(),
    );
    assert_eq!(
        dispatches.load(Ordering::SeqCst),
        0,
        "the backend must not have run: a retryable 503 for a call that DID execute is \
         how a store fault becomes repeated execution, since the retry carries a fresh \
         nonce the replay tier cannot refuse"
    );
}

/// Reserve and commit succeed, the backend runs, and completion then fails: neither success
/// exit (bodied 200, bodyless 202) is served. Both complete retention in the one success
/// exit, which refuses as indeterminate.
#[test]
fn a_success_whose_evidence_cannot_be_kept_after_execution_is_refused_on_both_exits() {
    let bodied_scratch = Scratch::new("indeterminate-bodied");
    let bodied = build_server_breaking_store_on_dispatch(
        bodied_scratch.retention(),
        bodied_scratch.join("evidence"),
    );
    assert_eq!(
        serve_one_full(&bodied, &unique_test_nonce()),
        (
            500,
            Some("mcp-re.evidence_retention_indeterminate".to_owned())
        ),
    );

    let notification_scratch = Scratch::new("indeterminate-notification");
    let notification = build_server_breaking_store_on_dispatch(
        notification_scratch.retention(),
        notification_scratch.join("evidence"),
    );
    assert_eq!(
        serve_one_notification(&notification, &unique_test_nonce()),
        500,
        "a 202 here would acknowledge a call the deployment cannot account for"
    );
}

fn indeterminate_request() -> mcp_re_http_profile::HttpRequest {
    mcp_re_http_profile::HttpRequest {
        method: "POST".to_owned(),
        target_uri: TARGET.to_owned(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

fn indeterminate_response() -> mcp_re_http_profile::HttpResponse {
    mcp_re_http_profile::HttpResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

/// R7-C018/C045/C058: the post-execution failure is a DIFFERENT state, and says so.
///
/// Reserve succeeds, so the call is dispatched; the store is then broken, so completion
/// fails. There is no transaction spanning the backend and the store, so this state is
/// unavoidable — what matters is that it is reported as indeterminate rather than as an
/// ordinary retryable outage, and that the reservation marker survives as the durable
/// record that this request crossed the execution threshold.
#[tokio::test]
async fn a_retention_failure_after_execution_is_indeterminate_and_leaves_its_reservation() {
    let scratch = Scratch::new("indeterminate");
    let evidence = scratch.join("evidence");
    let retention = EvidenceRetention::open(&evidence).expect("open retention");

    let reserved = retention
        .reserve(&indeterminate_request())
        .await
        .expect("reserve before dispatch");
    let digest = reserved.digest().as_str().to_owned();
    assert!(
        evidence.join(format!("{digest}.reserved")).exists(),
        "the obligation must be durable before anything relies on it"
    );
    let committed = retention
        .commit_to_dispatch(reserved)
        .await
        .expect("record the crossing before the side effects run");
    assert!(
        evidence.join(format!("{digest}.pending")).exists(),
        "the crossing must be durable before the side effects run"
    );

    // The backend has now "run". Break the store underneath the completion.
    replace_store_with_a_file(&evidence);

    retention
        .complete(&committed, &indeterminate_response())
        .await
        .expect_err("completion must fail once the store is gone");

    // Restore a directory so the marker's absence/presence is observable again.
    std::fs::remove_file(&evidence).expect("free the path");
    std::fs::create_dir_all(&evidence).expect("recreate the store directory");
    assert!(
        !evidence.join(&digest).exists(),
        "no hop was retained for the failed completion"
    );
}
