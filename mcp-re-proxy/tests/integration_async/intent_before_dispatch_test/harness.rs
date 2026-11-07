// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! The served deployment this suite drives: a counting backend, the network hop that drives
//! `handle` on a private runtime, and the client proxy over it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_re_client_proxy::transport::{RemoteTransport, TransportError};
use mcp_re_http_profile::{HttpRequest, HttpResponse};
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::HttpProfileProxy;

use crate::delegated_client_server_e2e_test::{client_proxy_over, params, NOW};

pub(crate) const REPLY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#;

/// An in-process backend that counts every dispatch it receives.
pub(crate) fn counting_inner(
    calls: Arc<AtomicUsize>,
) -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
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
    /// Lose the response after the proxy produced it, as a connection dropped before the
    /// write does (ADR-MCPRE-070 W6).
    discard: bool,
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
        if self.discard {
            return Err(TransportError::new(
                "the connection dropped before the write",
            ));
        }
        Ok(HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }
}

/// A served deployment: the client proxy, the backend counter and what the hop saw.
pub(crate) struct Deployment {
    pub(crate) client: mcp_re_client_proxy::ClientProxy,
    calls: Arc<AtomicUsize>,
    statuses: Arc<Mutex<Vec<u16>>>,
}

impl Deployment {
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn last_status(&self) -> Option<u16> {
        self.statuses.lock().expect("statuses").last().copied()
    }

    pub(crate) fn call(&self, body: &serde_json::Value) -> mcp_re_client_proxy::ProxyResponse {
        self.client
            .handle("r1", body, &params(&mcp_re_test_paths::unique_test_nonce()))
            .expect("the server's answer verifies")
    }
}

pub(crate) fn deploy(
    server: HttpProfileProxy,
    calls: Arc<AtomicUsize>,
    deadline: Option<Duration>,
) -> Deployment {
    deploy_with(server, calls, deadline, false)
}

/// [`deploy`], with a transport that loses every response after the proxy produced it.
pub(crate) fn deploy_with(
    server: HttpProfileProxy,
    calls: Arc<AtomicUsize>,
    deadline: Option<Duration>,
    discard: bool,
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
        discard,
    };
    Deployment {
        client: client_proxy_over(Box::new(hop)),
        calls,
        statuses,
    }
}
