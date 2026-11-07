//! The exchange with the etcd JSON gateway: one deadline-bounded JSON POST, and the two
//! requests the store issues over it (a lease grant and a put-if-absent transaction).
//!
//! Every failure — a transport error, a non-2xx status, an oversize body, unparseable
//! JSON, or the per-operation deadline — is [`ReplayStoreError::Unavailable`]: an outage
//! is never a fresh nonce.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::header;
use hyper::Method;
use hyper::Request;
use hyper_util::client::legacy::Client;
use serde_json::Value;

use super::gateway::GatewayConnector;
use super::protocol::build_lease_grant_body;
use super::protocol::build_txn_body;
use super::protocol::parse_lease_id;
use crate::shared_replay::ReplayStoreError;

/// A cap on the etcd gateway response body read into memory, so a broken/hostile
/// gateway cannot exhaust the proxy. Generous relative to a lease/txn JSON reply.
const MAX_ETCD_RESPONSE_BYTES: usize = 1024 * 1024;

/// The pooled `hyper` client, the gateway base URL and the deadline applied to each
/// round trip.
pub(super) struct Wire {
    client: Client<GatewayConnector, Full<Bytes>>,
    /// The etcd JSON-gateway base, e.g. `http://10.0.0.5:2379` (no trailing slash).
    base_url: String,
    /// Deadline applied to EACH gateway round trip. Never `None`: an unbounded
    /// authoritative-store call on the request path is the defect this closes.
    op_timeout: Duration,
}

impl Wire {
    pub(super) fn new(
        client: Client<GatewayConnector, Full<Bytes>>,
        base_url: &str,
        op_timeout: Duration,
    ) -> Self {
        Wire {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            op_timeout,
        }
    }

    pub(super) fn op_timeout(&self) -> Duration {
        self.op_timeout
    }

    /// Grant a lease living `ttl_secs`.
    pub(super) async fn grant_lease(&self, ttl_secs: i64) -> Result<i64, ReplayStoreError> {
        let reply = self
            .post("/v3/lease/grant", &build_lease_grant_body(ttl_secs))
            .await?;
        parse_lease_id(&reply)
    }

    /// The linearizable put-if-absent of `key_b64` under `lease_id`.
    pub(super) async fn put_if_absent(
        &self,
        key_b64: &str,
        lease_id: i64,
    ) -> Result<Value, ReplayStoreError> {
        // Value is the constant marker "1" (base64).
        let value_b64 = STANDARD.encode(b"1");
        self.post("/v3/kv/txn", &build_txn_body(key_b64, &value_b64, lease_id))
            .await
    }

    /// POST `body` as JSON to `path` on the gateway; return the parsed JSON reply.
    /// A non-2xx status, a transport error, an oversize body, or unparseable JSON
    /// all fail closed as [`ReplayStoreError::Unavailable`].
    async fn post(&self, path: &str, body: &Value) -> Result<Value, ReplayStoreError> {
        // One deadline over the WHOLE exchange — connect, send, status, and body read.
        // Bounding only the request would leave a gateway that accepts the request and
        // then trickles (or never finishes) the response just as able to park the caller.
        tokio::time::timeout(
            self.op_timeout,
            exchange(&self.client, &self.base_url, path, body),
        )
        .await
        .unwrap_or_else(|_| {
            Err(ReplayStoreError::Unavailable {
                details: format!(
                    "etcd POST {path} exceeded the {}ms per-operation deadline; failing \
                     closed (an unreachable authoritative store is never a fresh nonce)",
                    self.op_timeout.as_millis()
                ),
            })
        })
    }
}

fn unavailable(details: String) -> ReplayStoreError {
    ReplayStoreError::Unavailable { details }
}

/// The unbounded exchange, wrapped by [`Wire::post`]'s deadline.
pub(super) async fn exchange(
    client: &Client<GatewayConnector, Full<Bytes>>,
    base_url: &str,
    path: &str,
    body: &Value,
) -> Result<Value, ReplayStoreError> {
    let url = format!("{base_url}{path}");
    let payload = serde_json::to_vec(body)
        .map_err(|e| unavailable(format!("serialize etcd request body: {e}")))?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| unavailable(format!("build etcd request for {path}: {e}")))?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| unavailable(format!("etcd POST {path} failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(unavailable(format!(
            "etcd POST {path} returned status {}",
            resp.status()
        )));
    }
    let collected = http_body_util::Limited::new(resp.into_body(), MAX_ETCD_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|e| unavailable(format!("read etcd {path} response: {e}")))?;
    serde_json::from_slice(&collected.to_bytes())
        .map_err(|e| unavailable(format!("parse etcd {path} response JSON: {e}")))
}
