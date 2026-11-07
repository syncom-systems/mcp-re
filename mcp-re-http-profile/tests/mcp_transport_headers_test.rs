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
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
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

/// A JSON-RPC result: it carries no `method`.
const RESULT_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// An `initialize` request with no params.
const INITIALIZE_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;

const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

fn signed(extra: &[(&str, &str)]) -> HttpRequest {
    signed_post(extra, BODY)
}

fn signature_input(r: &HttpRequest) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .expect("signature-input present")
        .1
        .clone()
}

/// The signature parameters every request here is signed under.
fn signature_params(nonce: &str) -> RequestSignature<'_> {
    RequestSignature {
        key_id: CLIENT_KEY_ID,
        created: CREATED,
        expires: EXPIRES,
        nonce,
    }
}

/// An unsigned JSON POST to the MCP endpoint carrying `headers` (after `Content-Type`) and
/// `body`.
fn post(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    let mut all = vec![("Content-Type".to_string(), "application/json".to_string())];
    all.extend(
        headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: all,
        body: body.to_vec(),
    }
}

/// `post(headers, body)` signed by `sign`: through the profile (which derives and covers
/// the routing headers it can) or exactly as given (nothing derived or added).
fn signed_by<E>(
    sign: impl FnOnce(
        &mut HttpRequest,
        &SigningKey,
        &RequestSignature<'_>,
    ) -> Result<E, HttpProfileError>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpRequest {
    let mut r = post(headers, body);
    sign(
        &mut r,
        &client_key(),
        &signature_params(&unique_test_nonce()),
    )
    .expect("signs");
    r
}

fn signed_post(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    signed_by(sign_request, headers, body)
}

fn signed_post_as_given(headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    signed_by(sign_request_as_given, headers, body)
}

/// The refusal `policy` returns for `r`.
fn refusal(policy: &VerifierPolicy, r: &HttpRequest) -> HttpProfileError {
    Verifier::new(policy, &resolver())
        .verify_request_floor(r, NOW)
        .unwrap_err()
}

/// Rewrite the `Signature-Input` of `r` after signing, leaving every header on the wire.
fn rewrite_signature_input(r: &mut HttpRequest, rewrite: impl Fn(&str) -> String) {
    for h in r
        .headers
        .iter_mut()
        .filter(|h| h.0.eq_ignore_ascii_case("signature-input"))
    {
        h.1 = rewrite(&h.1);
    }
}

/// Remove `component` from the covered set of `r`, leaving the header itself on the wire.
fn strip_covered(r: &mut HttpRequest, component: &str) {
    rewrite_signature_input(r, |v| v.replace(&format!(" \"{component}\""), ""));
}

/// Add `component` to the covered set of `r`.
fn add_covered(r: &mut HttpRequest, component: &str) {
    rewrite_signature_input(r, |v| {
        v.replace(
            "\"content-type\"",
            &format!("\"content-type\" \"{component}\""),
        )
    });
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
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&r, NOW)
        .expect("covered-and-matching verifies");
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
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&r, NOW)
        .expect("a request the profile signed verifies under the mandatory contract");

    // Signed as given, with none of them: the contract is not optional, so it is refused.
    let bare = signed_post_as_given(&[], BODY);
    assert_eq!(
        refusal(&VerifierPolicy::default(), &bare),
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
    strip_covered(&mut r, "mcp-method");
    assert_eq!(
        refusal(&VerifierPolicy::default(), &r),
        HttpProfileError::MissingCoveredComponent("mcp-method"),
    );
}

#[test]
fn present_but_uncovered_mcp_name_is_rejected() {
    let mut r = signed(&[("Mcp-Method", "tools/call"), ("Mcp-Name", "read")]);
    strip_covered(&mut r, "mcp-name");
    assert_eq!(
        refusal(&VerifierPolicy::default(), &r),
        HttpProfileError::MissingCoveredComponent("mcp-name"),
    );
}

// --- negative: header/body divergence ---------------------------------------

/// The §4.1 gap this closes. The header and the body are BOTH covered and the
/// signature is valid — this is not tampering. It is the signer stating two
/// different methods, and the verifier refuses rather than picking one.
#[test]
fn header_body_method_divergence_is_rejected() {
    // The header says tools/list; the body says tools/call. The client really does sign
    // the contradiction.
    let r = signed_post(&[("Mcp-Method", "tools/list")], BODY);
    let err = refusal(&VerifierPolicy::default(), &r);
    assert_eq!(err, HttpProfileError::McpMethodDivergence);
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// Pin that the divergent request was otherwise perfectly valid: correct the
/// header to agree with the body, re-sign, and it verifies. So the divergence
/// check is what rejected it — not some incidental failure.
#[test]
fn the_divergent_request_is_otherwise_valid() {
    let r = signed(&[("Mcp-Method", "tools/call")]);
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&r, NOW)
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
    let r = signed_post(&[("Mcp-Method", "tools/call")], RESULT_BODY);
    let err = refusal(&VerifierPolicy::default(), &r);
    assert_eq!(err, HttpProfileError::McpMethodDivergence);
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// A result-shaped body carries no `method`, so no contract header is derivable for it and
/// the mandatory contract refuses it: a request the verifier admits names its method.
#[test]
fn a_result_shaped_body_carries_no_method_and_is_refused() {
    let r = signed_post(&[], RESULT_BODY);
    assert_eq!(
        refusal(&VerifierPolicy::default(), &r),
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
    add_covered(&mut r, "mcp-session-id");
    assert_eq!(
        refusal(&VerifierPolicy::default(), &r),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}

/// An unrelated foreign header stays rejected: widening the allowlist for the MCP
/// transport headers must not have opened it generally.
#[test]
fn the_component_allowlist_is_still_closed() {
    let mut r = signed(&[]);
    add_covered(&mut r, "x-acme-custom");
    assert_eq!(
        refusal(&VerifierPolicy::default(), &r),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}

// --- the full §4.1 transport contract (issue #425) ---------------------------
// The tests above cover header INTEGRITY (present ⇒ covered, mcp-method agreement).
// These cover the rest of §4.1 through the real verify path: required-header
// presence, the supported-version set, protocol-version/body agreement, and
// mcp-name agreement — all enforced AFTER the signature, against protected bytes.

use mcp_re_http_profile::McpTransportPolicy;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::VerifierPolicy;

fn strict_transport() -> VerifierPolicy {
    VerifierPolicy::default()
        .with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]))
}

/// A fully-conforming 2026-07-28 request verifies under the strict contract.
#[test]
fn conforming_2026_request_verifies_under_the_transport_contract() {
    let r = signed_post(
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "read"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        BODY,
    );
    Verifier::new(&strict_transport(), &resolver())
        .verify_request_floor(&r, NOW)
        .expect("a conforming request verifies");
}

/// A required header ABSENT is rejected — the gap the narrowed claim left open.
/// Under the strict contract, a POST with no `Mcp-Method` fails even though the
/// signature is valid.
#[test]
fn a_required_header_absent_is_rejected_through_verify() {
    let r = signed_post_as_given(&[("MCP-Protocol-Version", "2026-07-28")], INITIALIZE_BODY);
    let err = refusal(&strict_transport(), &r);
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
            ("Mcp-Method", "initialize"),
            ("MCP-Protocol-Version", "1999-01-01"),
        ],
        INITIALIZE_BODY,
    );
    let err = refusal(&strict_transport(), &r);
    assert_eq!(err, HttpProfileError::McpProtocolVersionUnsupported);
    assert_eq!(err.wire_code(), "mcp-re.unsupported_version");
}

/// Protocol-version header vs body `_meta` disagreement — the signer stating two
/// versions. Both are protected; the verifier refuses rather than picking one.
#[test]
fn protocol_version_header_body_divergence_is_rejected_through_verify() {
    let r = signed_post(
        &[
            ("Mcp-Method", "initialize"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}"#,
    );
    assert_eq!(
        refusal(&strict_transport(), &r),
        HttpProfileError::McpTransportDivergence("mcp-protocol-version")
    );
}

/// Mcp-Name disagreeing with params.name is rejected — the routing header must not
/// name a different tool than the signed body invokes.
#[test]
fn mcp_name_body_divergence_is_rejected_through_verify() {
    let r = signed_post(
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "delete"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        BODY,
    );
    assert_eq!(
        refusal(&strict_transport(), &r),
        HttpProfileError::McpTransportDivergence("mcp-name")
    );
}

/// Without a transport policy attached, behavior is unchanged: a request omitting
/// the headers verifies (the default VerifierPolicy enforces integrity of present
/// headers only). This pins that the contract is opt-in and additive.
#[test]
fn absent_headers_verify_when_no_transport_policy_is_attached() {
    let r = signed_post(&[], BODY);
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&r, NOW)
        .expect("no transport policy: present-header integrity only, absence allowed");
}
