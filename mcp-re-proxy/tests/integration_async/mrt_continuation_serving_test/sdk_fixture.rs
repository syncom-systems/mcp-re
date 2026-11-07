// SPDX-License-Identifier: Apache-2.0
//! The SDK-boundary fixtures: a delegated-signed exchange frozen under `sdk/fixtures`, so
//! both SDK bindings can prove they refuse a reply this reader cannot use.

use mcp_re_core::b64url_encode;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestRoleEvidence;

use super::harness::ready_signer;
use super::harness::root_key;
use super::harness::signed_request;
use super::harness::verified_reply_handle;
use super::harness::verify_request;
use super::harness::ACCESS_TOKEN;
use super::harness::AUD_SCOPE;
use super::harness::CLIENT_KEY_ID;
use super::harness::CLIENT_SEED;
use super::harness::CREATED;
use super::harness::EPOCH;
use super::harness::EXPIRES;
use super::harness::NOW;
use super::harness::OPEN_BODY;
use super::harness::ROOT_KID;
use super::harness::TARGET;
use super::harness::TTL;
use super::harness::VERIFIER_AUD;

/// Which recorded fixture a writer produces.
#[derive(Clone, Copy)]
pub(super) enum Recording {
    MalformedElicitation,
    UnrecognizedResultType,
}

impl Recording {
    /// The runfile variable naming the recorded fixture.
    fn runfile_variable(self) -> &'static str {
        match self {
            Recording::MalformedElicitation => "MCP_RE_SDK_FIXTURE_MALFORMED_ELICITATION",
            Recording::UnrecognizedResultType => "MCP_RE_SDK_FIXTURE_UNRECOGNIZED_RESULT_TYPE",
        }
    }
}

/// A reply to freeze, signed directly with the delegated custody the proxy uses: it stands
/// for a non-conformant or hostile server, the only place such a reply can now originate.
pub(super) struct SdkFixture<'a> {
    pub(super) recording: Recording,
    pub(super) nonce: &'a str,
    pub(super) reply_body: &'a [u8],
    pub(super) comment: &'a str,
}

/// The client's open-leg request, and the delegated reply signed over `reply_body`.
fn signed_exchange(
    nonce: &str,
    reply_body: &[u8],
) -> (HttpRequest, RequestRoleEvidence, HttpResponse) {
    // The delegated snapshot the proxy would sign with.
    let signer = ready_signer();
    let active = signer.current(NOW).expect("a delegated key is published");

    // The client's open-leg request, signed exactly as the SDK signs it.
    let (request, req_evidence) = signed_request(nonce, OPEN_BODY, None);

    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: reply_body.to_vec(),
    };
    let window = SigningWindow::over(active, NOW, TTL).expect("a live signing window");
    sign_delegated_response_full(&mut response, &request, &window)
        .expect("the reply signs — signing does not classify");

    // Precondition: this fixture is only meaningful if the response is otherwise GENUINE.
    // If it failed verification the SDKs would refuse it for the wrong reason and the test
    // would prove nothing.
    verify_request(&request);
    verified_reply_handle(&response, &request);
    (request, req_evidence, response)
}

fn fixture_json(
    spec: &SdkFixture<'_>,
    exchange: &(HttpRequest, RequestRoleEvidence, HttpResponse),
) -> serde_json::Value {
    let (request, req_evidence, response) = exchange;
    serde_json::json!({
        "_comment": spec.comment,
        "client_seed_b64url": b64url_encode(&CLIENT_SEED),
        "key_id": CLIENT_KEY_ID,
        "signer_id": "did:example:host-a",
        "nonce": spec.nonce,
        "created": CREATED,
        "expires": EXPIRES,
        "now": NOW,
        "target_uri": TARGET,
        "audience_id": VERIFIER_AUD,
        "route": "a",
        "dpop_token": ACCESS_TOKEN,
        "expected_audience_hash": AUD_SCOPE,
        "accepted_epochs": [EPOCH],
        "max_clock_skew": 60,
        "issuer": {
            "key_id": ROOT_KID,
            "pubkey_b64url": b64url_encode(&root_key().public_key().to_bytes()),
            "role": "server",
            "trust_domain": "example.com",
            "subject": "did:example:server",
        },
        "exchange": {
            "request_method": request.method,
            "request_target_uri": request.target_uri,
            "request_headers": request.headers,
            "request_body_b64url": b64url_encode(&request.body),
            "request_evidence_digest_alg": req_evidence.digest_alg(),
            "request_evidence_digest_value": req_evidence.digest_value(),
            "status": response.status,
            "headers": response.headers,
            "body_b64url": b64url_encode(&response.body),
        },
    })
}

impl SdkFixture<'_> {
    /// Rewrite the recording when `MCP_RE_WRITE_SDK_FIXTURE` is set; otherwise gate it.
    ///
    /// The recorded fixture is a runfile of this target. `bazel run` places runfiles as
    /// symlinks to the source files, so a regeneration writes through to `sdk/fixtures`.
    pub(super) fn write_or_gate(&self) {
        let exchange = signed_exchange(self.nonce, self.reply_body);
        let path = mcp_re_test_paths::resolve_runfile(self.recording.runfile_variable());
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&fixture_json(self, &exchange))
                .expect("fixture serializes")
        );

        if std::env::var("MCP_RE_WRITE_SDK_FIXTURE").is_ok() {
            std::fs::write(&path, &rendered).expect("write the SDK fixture");
            return;
        }

        // This is a GATE: the committed fixture must still be the one this code produces,
        // so a change to the signing path cannot silently leave both SDK suites asserting
        // against a stale recording.
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "{} is missing — regenerate it (see this test's doc)",
                path.display()
            )
        });
        assert_eq!(
            committed, rendered,
            "the committed SDK fixture has drifted from the signing path; regenerate it"
        );
    }
}
