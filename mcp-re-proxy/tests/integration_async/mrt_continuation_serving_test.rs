// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPS-047 stateless cross-replica MRTR continuation, end-to-end through the
//! production PEP (`HttpProfileProxy`) — the serving contract Proof 3 of
//! `docs/security/gke-multi-replica-validation.sh` exercises live.
//!
//! Two independent proxy instances (replica A and replica B) each with their OWN
//! delegated signer and OWN replay tier, but SHARING one continuation correlation
//! store (the in-process stand-in for the fleet-shared Redis tier). Proves:
//!   * OPEN on A: an eliciting inner returns an `InputRequiredResult` with a
//!     `requestState`; A delegated-signs it AND records the retained bases in the
//!     shared store.
//!   * ANSWER on B: a client signs the answer leg with an `HttpContinuation` (built
//!     from the two evidence-handle digests it already holds) + the `requestState`;
//!     B — which never saw the open leg — recovers the retained bases from the shared
//!     store, binds the continuation (digest equality under the client's signature),
//!     forwards to its inner, and delegated-signs a terminal reply. Honoured across a
//!     replica switch.
//!   * Fail-closed: a continuation with NO shared-store entry (never opened / expired
//!     / already answered — the store is one-shot), and a TAMPERED `requestState`,
//!     are both rejected `continuation_binding_failed`. A splice never admits.

mod envelopes;
mod harness;
mod inners;
mod legs;
mod replicas;
mod replies;
mod retention;
mod sdk_fixture;
mod stores;

mod binding_cases;
mod envelope_cases;
mod notification_cases;
mod open_leg_cases;
mod posture_cases;
mod retention_cases;
mod sdk_fixture_cases;
mod spent_approval_cases;

use std::sync::Arc;

use mcp_re_http_profile::HttpRequest;
use mcp_re_proxy::async_inner::DispatchedOutcome;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_test_paths::unique_test_nonce;

use harness::bare_proxy;
use harness::http_response;
use harness::ready_signer;
use harness::ready_signer_and_retirement;
use harness::second_actor;
use harness::served_of;
use harness::signed_request;
use harness::signer_with_credential_ttl;
use harness::verified_reply_handle;
use harness::verify_request;
use harness::NOW;
use harness::OPEN_BODY;
use harness::RESPONSE_SIG_TTL;
use inners::counter;
use inners::counting_inner;
use inners::eliciting_inner;
use inners::invocations;
use inners::malformed_eliciting_inner;
use inners::refusing;
use inners::replying_with;
use inners::reporting;
use inners::signer_retiring;
use inners::twice_eliciting_inner;
use legs::answer_body;
use legs::exchange;
use legs::open_on;
use legs::OpenLeg;
use replicas::notification_proxy;
use replicas::replica;
use replicas::replica_with_inner;
use replicas::replica_without_store;
use replicas::shared_store;
use replicas::two_replicas;
use replies::advertised_expiry;
use replies::assert_approval_spent_and_action_unrun;
use replies::assert_execution;
use replies::assert_not_possibly_executed;
use replies::assert_refused;
use replies::assert_retry_posture;
use replies::assert_signed_with_inline_delegation;
use replies::assert_states_no_continuation_or_retry_posture;
use replies::assert_status;
use replies::request_state_of;
use replies::result_type_of;
use replies::Refusal;
use replies::BINDING_FAILED;
use replies::CACHE_UNAVAILABLE;
use replies::INDETERMINATE;
use replies::INNER_PLANE_UNAVAILABLE;
use replies::POSSIBLY_EXECUTED;
use replies::RETENTION_UNAVAILABLE;
use replies::UPSTREAM_INVALID;
use retention::retention_in;
use sdk_fixture::Recording;
use sdk_fixture::SdkFixture;
use stores::Outage;
use stores::OutageStore;

const NOTIFICATION_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}"#;

/// Serve `request` on `proxy` at the frozen instant.
async fn serve(proxy: &HttpProfileProxy, request: &HttpRequest) -> ServedHttpResponse {
    proxy.handle(served_of(request), NOW).await
}

/// Serve a freshly signed open call (`OPEN_BODY`, a new nonce) on `proxy`.
async fn serve_open_call(proxy: &HttpProfileProxy) -> ServedHttpResponse {
    serve_body(proxy, OPEN_BODY).await
}

/// Serve a freshly signed `notifications/cancelled` on `proxy`.
async fn serve_notification(proxy: &HttpProfileProxy) -> ServedHttpResponse {
    serve_body(proxy, NOTIFICATION_BODY).await
}

async fn serve_body(proxy: &HttpProfileProxy, body: &[u8]) -> ServedHttpResponse {
    let (req, _ev) = signed_request(&unique_test_nonce(), body, None);
    serve(proxy, &req).await
}
