// SPDX-License-Identifier: Apache-2.0
//! The serving proxies the tests drive: fleet replicas sharing a continuation store, and
//! store-less proxies over a backend under the test's control.

use std::sync::Arc;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_inner::DispatchedOutcome;
use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::InMemoryContinuationStore;
use mcp_re_proxy::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

use super::harness::bare_proxy;
use super::harness::ready_signer;
use super::harness::RESPONSE_SIG_TTL;
use super::inners::eliciting_inner;
use super::inners::reporting;

/// One continuation correlation store, the in-process stand-in for the fleet-shared Redis
/// tier.
pub(super) fn shared_store() -> Arc<dyn AsyncContinuationStore> {
    Arc::new(InMemoryContinuationStore::new())
}

/// A serving proxy (its own signer + replay tier) over `inner`, sharing `store` — one fleet
/// replica.
pub(super) fn replica_with_inner(
    signer: Arc<DelegatedServerSigner>,
    store: Arc<dyn AsyncContinuationStore>,
    inner: Box<dyn AsyncInnerServer>,
) -> HttpProfileProxy {
    bare_proxy(inner, signer, RESPONSE_SIG_TTL)
        .with_continuation_store(store, DEFAULT_CONTINUATION_TTL_SECS)
}

/// A replica whose backend elicits with `request_state`.
pub(super) fn replica(
    signer: Arc<DelegatedServerSigner>,
    store: Arc<dyn AsyncContinuationStore>,
    request_state: &'static str,
) -> HttpProfileProxy {
    replica_with_inner(signer, store, eliciting_inner(request_state))
}

/// Replicas A and B, each with their OWN delegated signer and OWN replay tier, but SHARING
/// one continuation store.
pub(super) fn two_replicas(request_state: &'static str) -> (HttpProfileProxy, HttpProfileProxy) {
    let store = shared_store();
    (
        replica(ready_signer(), Arc::clone(&store), request_state),
        replica(ready_signer(), store, request_state),
    )
}

/// A proxy with NO continuation store, and an inner backend under the test's control.
pub(super) fn replica_without_store(inner: Box<dyn AsyncInnerServer>) -> HttpProfileProxy {
    bare_proxy(inner, ready_signer(), RESPONSE_SIG_TTL)
}

/// A store-less proxy whose inner plane reports `outcome` for every call.
pub(super) fn notification_proxy(outcome: DispatchedOutcome) -> HttpProfileProxy {
    replica_without_store(reporting(outcome))
}
