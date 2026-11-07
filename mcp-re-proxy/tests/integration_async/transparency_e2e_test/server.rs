// SPDX-License-Identifier: Apache-2.0
//! The real delegated-required server these lanes serve through, and the signed calls
//! they send it.

use super::fixtures::{
    client_key, resolver, root_key, ACCESS_TOKEN, AUD, CLIENT_KEY_ID, EPOCH, NOW, ROOT_KID, TARGET,
};
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::{ReplayAdmission, ReplayPosture};
use mcp_re_proxy::transparency::EvidenceRetention;
use mcp_re_proxy::HttpProfileProxy;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const OK_REPLY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#;
const UNRECOGNISED_RESULT_TYPE_REPLY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"something_new"}}"#;

fn server_config() -> mcp_re_proxy::deployment_request::DeploymentRequest {
    let args: Vec<String> = [
        "--bind",
        "127.0.0.1:8443",
        "--audience",
        AUD,
        "--allow-example-fixtures",
        "--server-signer",
        "did:example:server",
        "--server-key-id",
        ROOT_KID,
        "--signing-key-seed",
        "/dev/null",
        "--tls-cert",
        "/dev/null",
        "--tls-key",
        "/dev/null",
        "--client-ca",
        "/dev/null",
        "--trust",
        "/dev/null",
        "--inner-http-url",
        "http://127.0.0.1:9",
        "--target-uri",
        TARGET,
        "--mcp-protocol-version",
        "2026-07-28",
        "--route",
        "a",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
        "--replay-durability-tier",
        "redis-wait-quorum:1:100",
        "--delegated-trust-epoch",
        EPOCH,
        "--trust-domain",
        "mcp.example.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    mcp_re_proxy::cli::parse_args(&args)
        .expect("parse server config")
        .config()
        .clone()
}

/// The `SigningPlan` `app::run` projects, so this lane drives the production wiring
/// through the same plan the binary does — including the boundary that produces it.
fn signing_plan(
    config: &mcp_re_proxy::deployment_request::DeploymentRequest,
) -> mcp_re_proxy::startup_plan::SigningPlan {
    let validated =
        mcp_re_proxy::config_state::validation::ValidatedDeployment::try_from(config.clone())
            .expect("the fixture config must validate");
    mcp_re_proxy::startup_plan::response_authority_plans(&validated).1
}

/// The delegated-required server over an inner backend that answers with `reply`.
fn build_proxy(
    reply: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    retention: Option<Arc<EvidenceRetention>>,
) -> HttpProfileProxy {
    let config = server_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), root_key())
        .expect("the root states its key");
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("first delegated key");
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let proxy = HttpProfileProxy::new_delegated(
        resolver(),
        expected_audience,
        ReplayAdmission::new(
            AsyncReplayTier::new(
                Arc::new(InMemoryAsyncAtomicReplayStore::new()),
                mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
            ),
            ReplayPosture::SingleProcess,
        ),
        Box::new(mcp_re_proxy::async_inner::InProcessInner::new(
            reply,
            mcp_re_proxy::async_inner::DispatchCompletionBound::Within(std::time::Duration::ZERO),
        )),
        300,
        Arc::clone(&wiring.signer),
    );
    match retention {
        Some(retention) => proxy.with_evidence_retention(retention),
        None => proxy,
    }
}

pub(super) fn build_server(retention: Option<Arc<EvidenceRetention>>) -> HttpProfileProxy {
    build_proxy(|_forwarded: &[u8]| OK_REPLY.to_vec(), retention)
}

/// A server whose inner backend counts how many times it was actually invoked.
///
/// The distinction the retention state machine turns on is "the call definitely did not
/// execute" vs "it may have", so a test that only reads the status cannot tell whether
/// the refusal happened on the right side of the execution boundary.
pub(super) fn build_server_counting(
    retention: Option<Arc<EvidenceRetention>>,
    dispatches: Arc<AtomicUsize>,
) -> HttpProfileProxy {
    build_proxy(counting_reply(dispatches, OK_REPLY), retention)
}

/// A backend reply that counts each time it is asked.
fn counting_reply(
    dispatches: Arc<AtomicUsize>,
    reply: &'static [u8],
) -> impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static {
    move |_forwarded: &[u8]| {
        dispatches.fetch_add(1, Ordering::SeqCst);
        reply.to_vec()
    }
}

/// An inner plane that answers with an MCP result the protocol does not recognise, so the
/// exchange is refused AFTER the dispatch.
pub(super) fn build_server_refusing(
    retention: Option<Arc<EvidenceRetention>>,
    dispatches: Arc<AtomicUsize>,
) -> HttpProfileProxy {
    build_proxy(
        counting_reply(dispatches, UNRECOGNISED_RESULT_TYPE_REPLY),
        retention,
    )
}

/// `build_server` with retention on, whose backend breaks the evidence store when it runs,
/// so reserve and commit succeed and completion fails.
pub(super) fn build_server_breaking_store_on_dispatch(
    retention: Arc<EvidenceRetention>,
    evidence: std::path::PathBuf,
) -> HttpProfileProxy {
    build_proxy(
        move |_forwarded: &[u8]| {
            let _ = std::fs::remove_dir_all(&evidence);
            let _ = std::fs::write(&evidence, b"not a directory");
            OK_REPLY.to_vec()
        },
        Some(retention),
    )
}

fn signing_inputs(nonce: &str) -> RequestSigningInputs {
    RequestSigningInputs::new(
        CLIENT_KEY_ID.to_owned(),
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        },
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        nonce,
        NOW - 100,
        NOW + 200,
    )
    .with_headers(vec![(
        "Authorization".to_owned(),
        format!("Bearer {ACCESS_TOKEN}"),
    )])
}

fn handle(
    proxy: &HttpProfileProxy,
    signed: &mcp_re_client_core::SignedRequest,
) -> mcp_re_proxy::async_serve::ServedHttpResponse {
    let request = signed.request();
    let served = ServedHttpRequest {
        method: request.method.clone(),
        target_uri: request.target_uri.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
        peer: None,
        assertion: None,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async { proxy.handle(served, NOW).await })
}

/// Sign a plain request and serve it, returning the served status and the frozen
/// `mcp-re.*` reason the response body carries (a success carries none).
pub(super) fn serve_one_full(proxy: &HttpProfileProxy, nonce: &str) -> (u16, Option<String>) {
    let signed = mcp_re_client_core::build_signed_request(
        &serde_json::json!(1),
        "tools/call",
        serde_json::json!({"name": "read"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
        TARGET,
        &signing_inputs(nonce),
        &client_key(),
    )
    .expect("sign the request");
    let response = handle(proxy, &signed);
    let reason = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/wire_code")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        });
    (response.status, reason)
}

/// The status alone, for the calls that are expected to succeed.
pub(super) fn serve_one(proxy: &HttpProfileProxy, nonce: &str) -> u16 {
    serve_one_full(proxy, nonce).0
}

/// Serve one NOTIFICATION (a JSON-RPC message with no `id`), answered with a signed
/// bodyless 202.
pub(super) fn serve_one_notification(proxy: &HttpProfileProxy, nonce: &str) -> u16 {
    let signed = mcp_re_client_core::build_signed_notification(
        "notifications/cancelled",
        serde_json::Map::new(),
        TARGET,
        &signing_inputs(nonce),
        &client_key(),
    )
    .expect("sign the notification");
    handle(proxy, &signed).status
}
