// SPDX-License-Identifier: Apache-2.0
//! Request, response and signed-rejection vectors over the one signed base request.

use mcp_re_http_profile::rejection::pre_052_direct_root::build_pre_052_direct_root_rejection_for_negative_test;
use mcp_re_http_profile::rejection::pre_052_direct_root::sign_pre_052_direct_root_response_base_for_negative_test;
use mcp_re_http_profile::rejection::pre_052_direct_root_verifier::verify_pre_052_direct_root_rejection_for_negative_test;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::material::base_request;
use super::material::client_key;
use super::material::edit_signature_input;
use super::material::header_value;
use super::material::resolver;
use super::material::server_key;
use super::material::signed_at;
use super::material::signed_valid;
use super::material::valid_request;
use super::material::Header;
use super::material::SignatureInputEdit;
use super::material::CLIENT_KEY_ID;
use super::material::CREATED;
use super::material::EXPIRES;
use super::material::JSON;
use super::material::NOW;
use super::material::SERVER_KEY_ID;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Oracle;
use super::schema::Vector;

const OK_RESULT: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

fn response(content_type: &str, body: &[u8]) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), content_type.into())],
        body: body.to_vec(),
    }
}

/// Sign `response` as the server over the frozen window, bound to `request`.
fn sign_direct_root(response: &mut HttpResponse, request: &HttpRequest) {
    sign_pre_052_direct_root_response_base_for_negative_test(
        response,
        request,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");
}

fn request_valid() -> Fixture {
    let (request, evidence) = signed_valid();
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&request, NOW)
        .expect("fixture verifies");
    assert_eq!(&evidence, verified.evidence(), "writer sanity");
    // The oracle's base is the one the verifier accepted, taken from the verified product
    // rather than rebuilt over a component list that can drift from what the signer covers.
    let oracle = Oracle {
        signature_base_b64url: mcp_re_core::b64url_encode(verified.request_signature_base()),
        content_digest: header_value(&request, Header::ContentDigest),
        signature_header: header_value(&request, Header::Signature),
        request_evidence_digest_value: evidence.digest_value().to_owned(),
    };
    Fixture {
        oracle: Some(oracle),
        ..Vector {
            name: "h01_request_valid",
            kind: Kind::Request,
            expected: "verify_ok",
        }
        .for_request(&request)
    }
}

/// The base request signed under `key_id` over the `(created, expires)` window.
fn signed_under(key_id: &str, window: (i64, i64), nonce: &str) -> HttpRequest {
    let mut request = base_request();
    sign_request(
        &mut request,
        &client_key(),
        &RequestSignature {
            key_id,
            created: window.0,
            expires: window.1,
            nonce,
        },
    )
    .expect("signing succeeds");
    request
}

/// h01–h06 and h23: the request floor, valid and under each way it can fail.
pub(super) fn request_fixtures() -> Vec<Fixture> {
    let request = valid_request();
    let verdict = |name: &str, expected: &str, message: &HttpRequest| {
        Vector {
            name,
            kind: Kind::Request,
            expected,
        }
        .for_request(message)
    };

    // h02 — the body no longer matches the signed Content-Digest, so this is a precise
    // digest mismatch (MCPRE-92), not the old invalid_signature fold.
    let mut tampered = request.clone();
    tampered.body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm -rf"}}"#.to_vec();
    // h03 — content-digest stripped from the covered set after signing.
    let stripped = edit_signature_input(&request, SignatureInputEdit::DropContentDigest);
    // h04 — same evidence under a foreign profile tag.
    let foreign = edit_signature_input(&request, SignatureInputEdit::ForeignProfileTag);
    // h23 — a signature naming an algorithm that IS in the IANA HTTP Signature
    // Algorithms registry but is NOT in this verifier's local allowlist (#415 rev 2
    // §13.1). Registration is not deployment consent: the allowlist is the agility
    // mechanism, so this is rejected on POLICY, before any key resolution or crypto —
    // the same `unsupported_version` a foreign tag earns.
    let foreign_alg = edit_signature_input(&request, SignatureInputEdit::UnlistedAlgorithm);

    vec![
        request_valid(),
        verdict(
            "h02_request_body_tamper",
            "mcp-re.digest_mismatch",
            &tampered,
        ),
        verdict(
            "h03_request_missing_covered_component",
            "mcp-re.missing_envelope",
            &stripped,
        ),
        verdict(
            "h04_request_foreign_tag",
            "mcp-re.unsupported_version",
            &foreign,
        ),
        verdict(
            "h23_request_alg_not_allowlisted",
            "mcp-re.unsupported_version",
            &foreign_alg,
        ),
        // h05 — expired relative to the frozen NOW.
        verdict(
            "h05_request_stale_window",
            "mcp-re.expired_request",
            &signed_under(
                CLIENT_KEY_ID,
                (CREATED - 10_000, CREATED - 9_000),
                "vec-nonce-stale",
            ),
        ),
        // h06 — untrusted keyid, trust must fail first.
        verdict(
            "h06_request_wrong_keyid",
            "mcp-re.actor_binding_failed",
            &signed_under("rogue-key-9", (CREATED, EXPIRES), "vec-nonce-r"),
        ),
    ]
}

/// h07 and h08: a full signed exchange, and a response spliced onto another request.
pub(super) fn response_fixtures() -> Vec<Fixture> {
    let request = valid_request();
    let mut answer = response(JSON, OK_RESULT);
    sign_direct_root(&mut answer, &request);
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_bound_response_floor(&answer, &request, NOW)
        .expect("fixture verifies");

    // h08 — a response signed for request B presented as the answer to request A.
    let request_b = signed_at("https://mcp.example.com/mcp?route=b", "vec-nonce-2");
    let mut answer_b = response(JSON, OK_RESULT);
    sign_direct_root(&mut answer_b, &request_b);

    vec![
        Vector {
            name: "h07_response_valid",
            kind: Kind::Response,
            expected: "verify_ok",
        }
        .for_exchange(&request, &answer),
        // h08 — the splice: request A with B's response.
        Vector {
            name: "h08_response_splice",
            kind: Kind::Response,
            expected: "mcp-re.response_sig_invalid",
        }
        .for_exchange(&request, &answer_b),
    ]
}

/// h30 — SSE response on a covered exchange (#415 rev 2 §3.4, MCPRE-423).
/// The server GENUINELY signs it: the signature is valid and the digest
/// matches its body. It is rejected purely because a covered exchange is
/// JSON-mode only — per-event SSE evidence is deferred to a future
/// companion profile, so a stream here would be signed as a whole while
/// every event inside went unattested.
pub(super) fn sse_fixtures() -> Vec<Fixture> {
    let request = valid_request();
    let mut stream = response(
        "text/event-stream",
        b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
    );
    sign_direct_root(&mut stream, &request);
    vec![Vector {
        name: "h30_response_sse_on_covered_exchange",
        kind: Kind::Response,
        expected: "mcp-re.serialization_failed",
    }
    .for_exchange(&request, &stream)]
}

/// h18–h22: a rejection is a signed response carrying
/// `error.data.mcp_re_error.wire_code`. The valid request is the one the server binds
/// via `;req`.
const FORGED_REJECTION_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-31000,"message":"LIES","data":{"mcp_re_error":{"wire_code":"mcp-re.expired_request"}}}}"#;

/// The signed rejection bound to `request` and verified by the floor, and the unbound one
/// signed response-only.
fn signed_rejections(request: &HttpRequest) -> (HttpResponse, HttpResponse) {
    let reason = RejectionReason::new(
        "mcp-re.invalid_audience",
        "audience did not match this verifier (human text — do not trust)",
    );
    let reject = |bound_to: Option<&HttpRequest>, status: u16| {
        build_pre_052_direct_root_rejection_for_negative_test(
            bound_to,
            &reason,
            status,
            &server_key(),
            SERVER_KEY_ID,
            CREATED,
            EXPIRES,
        )
        .expect("rejection builds")
    };
    let bound = reject(Some(request), 403);
    verify_pre_052_direct_root_rejection_for_negative_test(
        &bound,
        Some(request),
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        NOW,
    )
    .expect("bound rejection verifies");
    (bound, reject(None, 400))
}

/// h18–h22: a rejection is a signed response carrying
/// `error.data.mcp_re_error.wire_code`. The valid request is the one the server binds
/// via `;req`.
pub(super) fn rejection_fixtures() -> Vec<Fixture> {
    let request = valid_request();
    // h18 — bound valid: the trusted wire code surfaces after the signature.
    // h19 — unbound valid: no request context, signed response-only.
    let (bound, unbound) = signed_rejections(&request);

    // h20 — body tamper: an edited human message breaks Content-Digest.
    let mut tampered = bound.clone();
    tampered.body = FORGED_REJECTION_BODY.to_vec();

    // h21 — splice: a rejection bound to the valid request presented against a
    // different request fails the ;req-covered signature.
    let other = signed_at("https://mcp.example.com/mcp?route=other", "vec-nonce-o");

    // h22 — unsigned: a bare JSON-RPC error with no signature is untrusted.
    let unsigned = HttpResponse {
        status: 403,
        headers: vec![("Content-Type".into(), JSON.into())],
        body: bound.body.clone(),
    };

    let exchange = |name: &str, expected: &str, request: &HttpRequest, answer: &HttpResponse| {
        Vector {
            name,
            kind: Kind::Rejection,
            expected,
        }
        .for_exchange(request, answer)
    };
    vec![
        exchange(
            "h18_rejection_bound_valid",
            "mcp-re.invalid_audience",
            &request,
            &bound,
        ),
        Fixture {
            request: None,
            ..exchange(
                "h19_rejection_unbound_valid",
                "mcp-re.invalid_audience",
                &request,
                &unbound,
            )
        },
        exchange(
            "h20_rejection_body_tamper",
            "mcp-re.digest_mismatch",
            &request,
            &tampered,
        ),
        exchange(
            "h21_rejection_splice",
            "mcp-re.response_sig_invalid",
            &other,
            &bound,
        ),
        exchange(
            "h22_rejection_unsigned",
            "mcp-re.missing_envelope",
            &request,
            &unsigned,
        ),
    ]
}
