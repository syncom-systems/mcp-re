// SPDX-License-Identifier: Apache-2.0
//! Bodyless signed-202 vectors (#415 rev 2 §3.4/§8.1, MCPRE-424).
//!
//! The 202 acknowledges a signed one-way notification POST. Its `;req` binding is the
//! ONLY binding it has (no body ⇒ no restated request_evidence), so the negatives below
//! target exactly that and the named-set boundaries.

use mcp_re_http_profile::bodyless::pre_052_fixtures::sign_pre_052_root_signed_202_for_negative_test;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use super::material::post;
use super::material::server_key;
use super::material::sign_as_client;
use super::material::CREATED;
use super::material::EXPIRES;
use super::material::JSON;
use super::material::SERVER_KEY_ID;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

const INITIALIZED: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const CANCELLED: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#;

fn signed_notification(body: &[u8], nonce: &str) -> HttpRequest {
    let mut notification = post(&[], body);
    sign_as_client(&mut notification, nonce);
    notification
}

fn fixture(
    name: &str,
    expected: &str,
    notification: &HttpRequest,
    acknowledgement: &HttpResponse,
) -> Fixture {
    Vector {
        name,
        kind: Kind::Bodyless202,
        expected,
    }
    .for_exchange(notification, acknowledgement)
}

/// h34–h37 and h50: the signed 202 bound to its notification, then each way the pairing
/// or the named set can be broken.
pub(super) fn bodyless_202_fixtures() -> Vec<Fixture> {
    let note = signed_notification(INITIALIZED, "vec-nonce-note");
    let ack = sign_pre_052_root_signed_202_for_negative_test(
        &note,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("the PEP signs its acceptance");

    // h35 — content-type present when the named set says it must be absent.
    let mut ack_ct = ack.clone();
    ack_ct.headers.push(("Content-Type".into(), JSON.into()));

    // h36 — content injected into a message whose digest commits to empty content.
    let mut ack_body = ack.clone();
    ack_body.body = br#"{"cancelled":true}"#.to_vec();

    // h37 — the splice: A's acknowledgement presented against notification B. Since
    // C019b the verdict is `request_binding_mismatch`, not `response_sig_invalid`: the
    // acknowledgement carries the request-evidence coordinate of the transmission it
    // answers, the verifier re-derives that coordinate from the request in front of it,
    // and the mismatch is caught BEFORE the signature check. The more precise verdict
    // is the point — it names why the pairing is wrong rather than only that the bytes
    // did not verify.
    let note_b = signed_notification(CANCELLED, "vec-nonce-note-b");

    // h50 — the TRANSMISSION-distinct splice (owner ruling C019b). A′ is byte-identical
    // to A in method, target and body and differs only in the nonce inside its own
    // `@signature-params` — the ordinary case for a retried `notifications/cancelled`.
    // A's acknowledgement must not verify for it, or a captured 202 could be presented
    // as proof of acceptance for a transmission the server in fact refused as a replay.
    // h37 covers the content-distinct half; this one is what content-level binding could
    // not express at all.
    let note_a_prime = signed_notification(INITIALIZED, "vec-nonce-note-retransmission");
    assert_eq!(
        note.body, note_a_prime.body,
        "the two transmissions are content-identical"
    );

    vec![
        fixture("h34_bodyless_202_valid", "verify_ok", &note, &ack),
        fixture(
            "h35_bodyless_202_content_type_present",
            "mcp-re.malformed_envelope",
            &note,
            &ack_ct,
        ),
        fixture(
            "h36_bodyless_202_content_injected",
            "mcp-re.malformed_envelope",
            &note,
            &ack_body,
        ),
        fixture(
            "h37_bodyless_202_splice",
            "mcp-re.request_binding_mismatch",
            &note_b,
            &ack,
        ),
        fixture(
            "h50_bodyless_202_retransmission",
            "mcp-re.request_binding_mismatch",
            &note_a_prime,
            &ack,
        ),
    ]
}
