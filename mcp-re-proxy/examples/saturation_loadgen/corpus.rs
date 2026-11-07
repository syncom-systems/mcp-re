// SPDX-License-Identifier: Apache-2.0
//! The pre-signed request corpus: every signature happens here, before the clock starts.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_client_core::build_signed_message;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::McpMessage;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::SignedRequest;
use mcp_re_core::SigningKey;

use serde_json::Map;
use serde_json::Value;

use super::args::Args;

const AUDIENCE: &str = "did:example:server-1";
const SIGNER_A_KEY_ID: &str = "key-a";
const TARGET_URI: &str = "https://localhost/";
const DPOP_TOKEN: &str = "loadgen-dpop-token";

pub(super) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Sign every request the run will send, as wire bytes ready to write.
pub(super) fn build(a: &Args) -> Vec<Vec<u8>> {
    let signer = SigningKey::from_seed_bytes(&[1u8; 32]);
    let salt = nonce_salt(a);
    (0..a.requests)
        .map(|i| {
            let signed = sign(&format!("sat-{salt}-{}-{i}", a.id), &signer);
            let mut bytes = wire(&signed, a.keep_alive());
            if a.tamper {
                tamper(&mut bytes);
            }
            bytes
        })
        .collect()
}

/// The nonce must be unique across RUNS, not just across generators within one run.
/// It used to be `sat-{id}-{i}`, which is identical in every run — so the
/// orchestrator's M+1 saturation probe replayed the measurement run's corpus verbatim
/// and the proxy correctly rejected 6 of every 7 requests at the replay tier. Those
/// rejections skip the backend AND the response signature, so they are cheap, the
/// probe looked FASTER than the run it was probing, and every row was stamped CLIENT
/// on a gain that was pure replay rejection. The pid/start salt makes each process's
/// corpus its own.
fn nonce_salt(a: &Args) -> String {
    a.nonce_salt.clone().unwrap_or_else(|| {
        format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )
    })
}

/// Sign one request. Called only during the pre-signing phase.
fn sign(nonce: &str, key: &SigningKey) -> SignedRequest {
    let nonce = format!("{nonce}-padded-to-the-128-bit-floor");
    let now = now_unix();
    let audience = AudienceTuple {
        audience_id: AUDIENCE.to_string(),
        target_uri: TARGET_URI.to_string(),
        route: None,
    };
    let binding = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, DPOP_TOKEN.as_bytes());
    let inputs = RequestSigningInputs::new(
        SIGNER_A_KEY_ID,
        audience,
        vec![binding],
        &nonce,
        now,
        // Wide enough that a long pre-signing phase cannot expire the head of the
        // corpus before the tail is sent.
        now + 3600,
    )
    .with_headers(vec![(
        "Authorization".to_string(),
        format!("Bearer {DPOP_TOKEN}"),
    )]);
    let mut params = Map::new();
    params.insert("text".to_string(), Value::String("hello".to_string()));
    build_signed_message(
        McpMessage::new(Some(&Value::String("req-1".to_string())), "echo", params),
        TARGET_URI,
        &inputs,
        key,
    )
    .expect("sign")
}

/// Serialise a signed request to wire bytes once, so the hot loop only writes.
fn wire(signed: &SignedRequest, keep_alive: bool) -> Vec<u8> {
    let req = signed.request();
    let mut head = String::new();
    head.push_str("POST / HTTP/1.1\r\nHost: localhost\r\n");
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    for (name, value) in &req.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", req.body.len()));
    let mut out = head.into_bytes();
    out.extend_from_slice(&req.body);
    out
}

/// Change the signed echo text in place, keeping the length, so the body no longer
/// matches the digest the signature covers.
fn tamper(wire: &mut [u8]) {
    let at = wire
        .windows(5)
        .rposition(|w| w == b"hello")
        .expect("the signed body carries the echo text");
    wire[at] = b'j';
}
