// SPDX-License-Identifier: Apache-2.0
//! Building signed calls and reading the wire answer.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::async_serve::ServedHttpRequest;

use super::fixtures::audience;
use super::fixtures::client_key;
use super::fixtures::issue_assertion;
use super::fixtures::CLIENT_KEY_ID;
use super::fixtures::CREATED;
use super::fixtures::EXPIRES;
use super::fixtures::TARGET;

/// A call signed by the client carrying exactly the admission evidence given: a binding,
/// an assertion, both or neither, with no check that they describe the same admission.
/// `nonce` must be fresh per call: the replay tier is real here.
pub(super) fn evidence_call(
    binding: Option<AdmissionBinding>,
    assertion: Option<String>,
    nonce: &str,
) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    };
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: binding,
        admission_assertion: assertion,
        authorization_decision: None,
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce,
        },
    )
    .expect("signs");
    req
}

/// A signed call, optionally declaring the admission it acts under: the binding derived from
/// the claims, and the assertion over them signed by the given key.
pub(super) fn signed_call(
    admission: Option<(&AdmissionClaims, &SigningKey)>,
    nonce: &str,
) -> HttpRequest {
    let evidence =
        admission.map(|(c, k)| (AdmissionBinding::opaque_from(c), issue_assertion(c, k)));
    let (binding, assertion) = match evidence {
        Some((binding, assertion)) => (Some(binding), Some(assertion)),
        None => (None, None),
    };
    evidence_call(binding, assertion, nonce)
}

pub(super) fn served_of(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        peer: None,
        assertion: None,
    }
}

pub(super) fn wire_code_of(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")?
                .get("data")?
                .get("mcp_re_error")?
                .get("wire_code")?
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

pub(super) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}
