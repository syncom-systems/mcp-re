// SPDX-License-Identifier: Apache-2.0
//! The one signed request both legs POST.

use serde_json::json;

use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::PROFILE_TAG;

use crate::hpp_common;

/// The request evidence block. It requires at least one artifact binding; we bind an
/// OAuth DPoP credential, whose bytes the verifier derives from the covered
/// `Authorization: Bearer` header.
fn evidence_block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: hpp_common::audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            hpp_common::ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    }
}

/// A plain MCP tools/call (add(2,40)) — the payload the backend actually runs — signed at
/// `now` under `nonce`. `sign_request_full` inserts the evidence block, then emits
/// Content-Digest + Signature-Input + Signature (covering the Authorization header because
/// it is present).
pub fn signed_call(target: &str, now: i64, nonce: &str) -> HttpRequest {
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "add", "arguments": { "a": 2, "b": 40 } }
    });
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: target.to_owned(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            (
                "Authorization".into(),
                format!("Bearer {}", hpp_common::ACCESS_TOKEN),
            ),
        ],
        body: serde_json::to_vec(&call).expect("serialize call"),
    };
    // The delegated verifier binds the response to THIS request's evidence handle, so
    // keep what signing produced rather than recomputing it.
    let _request_evidence = sign_request_full(
        &mut request,
        &evidence_block(),
        &hpp_common::client_key(),
        hpp_common::CLIENT_KEY_ID,
        now,
        now + 300,
        nonce,
    )
    .expect("sign request");
    request
}
