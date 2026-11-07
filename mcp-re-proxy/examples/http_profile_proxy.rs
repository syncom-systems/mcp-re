// SPDX-License-Identifier: Apache-2.0
//! `http_profile_proxy` — a networked MCP-RE **HTTP-profile** proxy front that
//! forwards to a real **Streamable-HTTP** MCP backend (FastMCP). This is the
//! ADR-MCPRE-050 go-forward carrier wired end-to-end over the wire, using the
//! proxy's own verify / replay / forward / sign code — NOT the object/legacy path
//! and NOT a stdio inner.
//!
//! Per POST it runs the real pipeline:
//!   1. reconstruct the `HttpRequest` (method, `@target-uri`, headers, body);
//!   2. `verify_request_full` — RFC 9421 signature + RFC 9530 Content-Digest +
//!      the request evidence block (audience/artifact bindings);
//!   3. `ReplayAdmission::admit` — replay admission (fail-closed), the same entry point
//!      the shipped serving path's `answering_commitment` awaits;
//!   4. strip the proxy-owned top-level `_meta` and forward the clean JSON-RPC to
//!      the Streamable-HTTP backend through the proxy's real `HttpInnerPool`;
//!   5. `sign_delegated_response_full` — sign the backend's reply under a `SigningWindow`
//!      over the DELEGATED key, bound to THIS request, carrying the root-signed credential
//!      that authorizes it (ADR-MCPRE-052 delegated-required) — or, for a one-way
//!      notification, `sign_delegated_accepted_202` (#424 / #418).
//!
//! Any fail-closed step emits a DELEGATED-signed rejection receipt instead — bound to
//! the request once it has verified, preflight (unbound) before that.
//!
//! This proof front is PLAIN HTTP: the HTTP-profile security is application-layer
//! (RFC 9421 request/response signatures), so a plain-HTTP local proof isolates the
//! profile crypto. mTLS transport binding is an additive layer folded in later.
//!
//! Launch (addresses come from config/ports.toml via the environment, never a
//! literal):
//!   HPP_BIND=127.0.0.1:8601 \
//!   HPP_INNER_URL=http://127.0.0.1:8620/mcp/ \
//!   HPP_TARGET=http://127.0.0.1:8601/mcp \
//!   bazel run //mcp-re-proxy:http_profile_proxy

use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use mcp_re_proxy::continuation_store::InMemoryContinuationStore;
use mcp_re_proxy::http_inner::HttpInnerPool;
use mcp_re_proxy::http_profile_dispatch::ReplayAdmission;
use mcp_re_proxy::http_profile_serve::continuation::ContinuationPlane;
use mcp_re_proxy::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS;

// Shared demo material; each example uses a different subset, so allow dead code.
#[allow(dead_code)]
#[path = "hpp_common/mod.rs"]
mod hpp_common;

#[path = "http_profile_proxy/body.rs"]
mod body;
#[path = "http_profile_proxy/pipeline.rs"]
mod pipeline;
#[path = "http_profile_proxy/receipts.rs"]
mod receipts;
#[path = "http_profile_proxy/replay.rs"]
mod replay;

/// Shared proxy state: the inner-plane client pool and the replay admission (an in-memory
/// single-process tier OR a shared Redis tier, with the posture declared for it). All
/// shared across connections — replay must be detected across requests AND, with a
/// shared tier, across replicas.
struct ProxyState {
    inner: HttpInnerPool,
    replay: ReplayAdmission,
    /// The ADR-MCPS-047 continuation plane the serving path runs, over an in-memory
    /// store because this front is one process: it carries a multi-round-trip call across
    /// its two legs, and makes no cross-replica claim. A fleet wires the shared Redis store
    /// instead — the difference is the store, not the protocol.
    continuations: ContinuationPlane,
}

impl ProxyState {
    fn new(inner_url: &str, replay: ReplayAdmission) -> Self {
        let inner_uri = inner_url.parse().expect("HPP_INNER_URL is a valid URI");
        ProxyState {
            inner: HttpInnerPool::new(vec![inner_uri], Duration::from_secs(10))
                .expect("build inner pool"),
            replay,
            continuations: ContinuationPlane::wired(
                Arc::new(InMemoryContinuationStore::new()),
                DEFAULT_CONTINUATION_TTL_SECS,
            ),
        }
    }
}

#[tokio::main]
async fn main() {
    let bind = std::env::var("HPP_BIND").expect("HPP_BIND (e.g. 127.0.0.1:8601)");
    let inner_url =
        std::env::var("HPP_INNER_URL").expect("HPP_INNER_URL (e.g. http://127.0.0.1:8620/mcp/)");
    let (replay, fleet_strict) = replay::from_env().await;
    let state = Arc::new(ProxyState::new(&inner_url, replay));

    let listener = TcpListener::bind(&bind).await.expect("bind HPP_BIND");
    eprintln!(
        "http_profile_proxy: listening on http://{bind}  ->  inner {inner_url}  (target {}; fleet_strict={})",
        hpp_common::target(),
        fleet_strict
    );

    loop {
        let Ok((tcp, _peer)) = listener.accept().await else {
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(tcp);
            let service = service_fn(move |req| pipeline::handle(Arc::clone(&state), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}
