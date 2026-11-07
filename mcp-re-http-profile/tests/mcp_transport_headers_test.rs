// SPDX-License-Identifier: Apache-2.0
//! MCP transport-header coverage (#415 rev 2 §4.1, issue #425).
//!
//! `Mcp-Method` states, in the clear, which JSON-RPC method a request carries.
//! Uncovered, that claim can diverge from the signed body: an intermediary reads
//! `tools/list` off the header and routes, logs, or authorizes on it while the
//! signed body says `tools/call`. The proxy never routes on these headers
//! (ADR-MCPS-025 — they are untrusted hints, the body is authoritative), but a
//! covered header cannot LIE about a signed body, which is worth more than a
//! header nobody is permitted to believe.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign::sign_request_as_given;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::McpTransportPolicy;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_test_paths::unique_test_nonce;

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: key_id.into(),
            },
            verification_key: client_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

/// An unsigned POST of `body` carrying `headers`.
fn post(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        body: body.to_vec(),
    }
}

/// The signer under test: the profile's signer or the as-given one.
type Signer = fn(
    &mut HttpRequest,
    &SigningKey,
    &RequestSignature<'_>,
) -> Result<RequestRoleEvidence, HttpProfileError>;

/// A POST signed by `sign` as the client.
fn signed_by(sign: Signer, headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    let mut r = post(headers, body);
    sign(
        &mut r,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce: &unique_test_nonce(),
        },
    )
    .expect("signs");
    r
}

/// A POST signed through the profile, which derives and covers the routing headers.
fn signed_post(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    signed_by(sign_request, headers, body)
}

/// A POST signed with exactly the headers it was given.
fn signed_post_as_given(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    signed_by(sign_request_as_given, headers, body)
}

/// The standard tools/call POST with `extra` headers beside its content type.
fn signed(extra: &[(&str, &str)]) -> HttpRequest {
    let mut headers = vec![("Content-Type", "application/json")];
    headers.extend_from_slice(extra);
    signed_post(&headers, BODY)
}

/// What the verifier's floor makes of `r` under `policy`.
fn verify_floor(r: &HttpRequest, policy: &VerifierPolicy) -> Result<(), HttpProfileError> {
    Verifier::new(policy, &resolver())
        .verify_request_floor(r, NOW)
        .map(|_| ())
}

/// The refusal the verifier's floor gives `r` under `policy`.
fn floor_error(r: &HttpRequest, policy: &VerifierPolicy) -> HttpProfileError {
    verify_floor(r, policy).unwrap_err()
}

/// Rewrite the request's `Signature-Input` value, leaving every other header on the wire.
fn replace_in_signature_input(r: &mut HttpRequest, from: &str, to: &str) {
    for (name, value) in r.headers.iter_mut() {
        if name.eq_ignore_ascii_case("signature-input") {
            *value = value.replace(from, to);
        }
    }
}

fn signature_input(r: &HttpRequest) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .expect("signature-input present")
        .1
        .clone()
}

// --- positive: covered and matching -----------------------------------------

#[test]
fn mcp_transport_headers_are_covered_when_present() {
    let r = signed(&[
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "read"),
        ("Mcp-Protocol-Version", "2026-07-28"),
    ]);
    let input = signature_input(&r);
    for expected in ["\"mcp-method\"", "\"mcp-name\"", "\"mcp-protocol-version\""] {
        assert!(
            input.contains(expected),
            "the signer must cover {expected} when it is present: {input}"
        );
    }
    verify_floor(&r, &VerifierPolicy::default()).expect("covered-and-matching verifies");
}

/// A deployment whose protocol version does not define these headers never sends
/// them, and signs exactly what it signed before — the rule is
/// version-conditional without the signer being told which version it is on.
#[test]
fn the_signer_derives_and_covers_the_headers_and_a_request_omitting_them_is_refused() {
    // Signed through the profile: the three routing headers are derived from the body and
    // covered, so the request satisfies the contract without the caller stating them.
    let r = signed(&[]);
    let input = signature_input(&r);
    for covered in ["mcp-method", "mcp-name", "mcp-protocol-version"] {
        assert!(
            input.contains(covered),
            "{covered} must be covered: {input}"
        );
    }
    verify_floor(&r, &VerifierPolicy::default())
        .expect("a request the profile signed verifies under the mandatory contract");

    // Signed as given, with none of them: the contract is not optional, so it is refused.
    let bare = signed_post_as_given(
        &[("Content-Type", "application/json")],
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
    );
    assert_eq!(
        floor_error(&bare, &VerifierPolicy::default()),
        HttpProfileError::McpTransportHeaderMissing("mcp-method"),
    );
}

// --- negative: present but uncovered ----------------------------------------

/// The conditional-mandatory rule, on the `authorization`/`dpop` pattern: a
/// present header that is not covered is rejected. Otherwise a sender could
/// attach an unsigned method claim to a signed request and have it read
/// downstream as though the signature stood behind it.
#[test]
fn present_but_uncovered_mcp_method_is_rejected() {
    let mut r = signed(&[("Mcp-Method", "tools/call")]);
    // Strip it from the covered set post-signing, leaving the header on the wire.
    replace_in_signature_input(&mut r, " \"mcp-method\"", "");
    assert_eq!(
        floor_error(&r, &VerifierPolicy::default()),
        HttpProfileError::MissingCoveredComponent("mcp-method"),
    );
}

#[test]
fn present_but_uncovered_mcp_name_is_rejected() {
    let mut r = signed(&[("Mcp-Method", "tools/call"), ("Mcp-Name", "read")]);
    replace_in_signature_input(&mut r, " \"mcp-name\"", "");
    assert_eq!(
        floor_error(&r, &VerifierPolicy::default()),
        HttpProfileError::MissingCoveredComponent("mcp-name"),
    );
}

// --- negative: header/body divergence ---------------------------------------

/// The §4.1 gap this closes. The header and the body are BOTH covered and the
/// signature is valid — this is not tampering. It is the signer stating two
/// different methods, and the verifier refuses rather than picking one.
#[test]
fn header_body_method_divergence_is_rejected() {
    let r = signed_post(
        &[
            ("Content-Type", "application/json"),
            // The header says tools/list; the body below says tools/call.
            ("Mcp-Method", "tools/list"),
        ],
        BODY,
    );

    let err = floor_error(&r, &VerifierPolicy::default());
    assert_eq!(err, HttpProfileError::McpMethodDivergence);
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// Pin that the divergent request was otherwise perfectly valid: correct the
/// header to agree with the body, re-sign, and it verifies. So the divergence
/// check is what rejected it — not some incidental failure.
#[test]
fn the_divergent_request_is_otherwise_valid() {
    let r = signed(&[("Mcp-Method", "tools/call")]);
    verify_floor(&r, &VerifierPolicy::default())
        .expect("the same request with an agreeing header verifies");
}

/// An `Mcp-Method` header on a body that HAS no method is refused.
///
/// This shape — a result body carrying a signed `Mcp-Method: tools/call` — is the
/// one case where the §4.1 agreement rule has nothing to compare against, so the
/// header's value would be constrained by nothing while still carrying the signer's
/// full authenticity. An intermediary that routes, rate-limits or audits on the
/// header (the stated reason §4.1 covers it) would act on an arbitrary string. The
/// header may only accompany the `method` it mirrors.
#[test]
fn an_mcp_method_header_with_no_body_method_is_rejected() {
    let r = signed_post(
        &[
            ("Content-Type", "application/json"),
            ("Mcp-Method", "tools/call"),
        ],
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
    );
    let err = floor_error(&r, &VerifierPolicy::default());
    assert_eq!(err, HttpProfileError::McpMethodDivergence);
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// A result-shaped body carries no `method`, so no contract header is derivable for it and
/// the mandatory contract refuses it: a request the verifier admits names its method.
#[test]
fn a_result_shaped_body_carries_no_method_and_is_refused() {
    let r = signed_post(
        &[("Content-Type", "application/json")],
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
    );
    assert_eq!(
        floor_error(&r, &VerifierPolicy::default()),
        HttpProfileError::McpTransportHeaderMissing("mcp-method"),
    );
}

// --- session-id is scoped out ------------------------------------------------

/// `mcp-session-id` is NOT coverable: protocol sessions are a 2025-11-25 concept
/// that 2026-07-28 removes, and MCP-RE's serving path is stateless per-request by
/// design — there is no session for a session id to identify. Covering it would
/// manufacture the appearance of a binding over nothing, so the closed allowlist
/// rejects it as an unknown covered component. That is the intended answer.
#[test]
fn mcp_session_id_is_not_a_coverable_component() {
    let mut r = signed(&[("Mcp-Session-Id", "sess-1")]);
    // The signer did not cover it (it is not in the coverable set)...
    assert!(!signature_input(&r).contains("mcp-session-id"));
    // ...and a sender that hand-crafts it into the covered set is rejected.
    replace_in_signature_input(
        &mut r,
        "\"content-type\"",
        "\"content-type\" \"mcp-session-id\"",
    );
    assert_eq!(
        floor_error(&r, &VerifierPolicy::default()),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}

/// An unrelated foreign header stays rejected: widening the allowlist for the MCP
/// transport headers must not have opened it generally.
#[test]
fn the_component_allowlist_is_still_closed() {
    let mut r = signed(&[]);
    replace_in_signature_input(
        &mut r,
        "\"content-type\"",
        "\"content-type\" \"x-acme-custom\"",
    );
    assert_eq!(
        floor_error(&r, &VerifierPolicy::default()),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}

// --- the full §4.1 transport contract (issue #425) ---------------------------
// The tests above cover header INTEGRITY (present ⇒ covered, mcp-method agreement).
// These cover the rest of §4.1 through the real verify path: required-header
// presence, the supported-version set, protocol-version/body agreement, and
// mcp-name agreement — all enforced AFTER the signature, against protected bytes.

fn strict_transport() -> VerifierPolicy {
    VerifierPolicy::default()
        .with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]))
}

/// The tools/call request for `read`, with an `Mcp-Name` header naming `named`.
fn strict_call_naming(named: &str) -> HttpRequest {
    signed_post(
        &[
            ("Content-Type", "application/json"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", named),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        BODY,
    )
}

/// A fully-conforming 2026-07-28 request verifies under the strict contract.
#[test]
fn conforming_2026_request_verifies_under_the_transport_contract() {
    let r = strict_call_naming("read");
    verify_floor(&r, &strict_transport()).expect("a conforming request verifies");
}

/// A required header ABSENT is rejected — the gap the narrowed claim left open.
/// Under the strict contract, a POST with no `Mcp-Method` fails even though the
/// signature is valid.
#[test]
fn a_required_header_absent_is_rejected_through_verify() {
    let r = signed_post_as_given(
        &[
            ("Content-Type", "application/json"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    let err = floor_error(&r, &strict_transport());
    assert_eq!(
        err,
        HttpProfileError::McpTransportHeaderMissing("mcp-method")
    );
    assert_eq!(err.wire_code(), "mcp-re.missing_envelope");
}

/// An unsupported protocol version is rejected — a client's claim is not consent.
#[test]
fn an_unsupported_protocol_version_is_rejected_through_verify() {
    let r = signed_post(
        &[
            ("Content-Type", "application/json"),
            ("Mcp-Method", "initialize"),
            ("MCP-Protocol-Version", "1999-01-01"),
        ],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    let err = floor_error(&r, &strict_transport());
    assert_eq!(err, HttpProfileError::McpProtocolVersionUnsupported);
    assert_eq!(err.wire_code(), "mcp-re.unsupported_version");
}

/// Protocol-version header vs body `_meta` disagreement — the signer stating two
/// versions. Both are protected; the verifier refuses rather than picking one.
#[test]
fn protocol_version_header_body_divergence_is_rejected_through_verify() {
    let r = signed_post(&[("Content-Type", "application/json"),
            ("Mcp-Method", "initialize"),
            ("MCP-Protocol-Version", "2026-07-28"),], br#"{"jsonrpc":"2.0","id":1,"method":"initialize","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}"#);
    let err = floor_error(&r, &strict_transport());
    assert_eq!(
        err,
        HttpProfileError::McpTransportDivergence("mcp-protocol-version")
    );
}

/// Mcp-Name disagreeing with params.name is rejected — the routing header must not
/// name a different tool than the signed body invokes.
#[test]
fn mcp_name_body_divergence_is_rejected_through_verify() {
    let r = strict_call_naming("delete");
    let err = floor_error(&r, &strict_transport());
    assert_eq!(err, HttpProfileError::McpTransportDivergence("mcp-name"));
}

/// Without a transport policy attached, behavior is unchanged: a request omitting
/// the headers verifies (the default VerifierPolicy enforces integrity of present
/// headers only). This pins that the contract is opt-in and additive.
#[test]
fn absent_headers_verify_when_no_transport_policy_is_attached() {
    let r = signed_post(
        &[("Content-Type", "application/json")],
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
    );
    verify_floor(&r, &VerifierPolicy::default())
        .expect("no transport policy: present-header integrity only, absence allowed");
}
