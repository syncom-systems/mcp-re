// SPDX-License-Identifier: Apache-2.0
//! MCP transport-header (#415 rev 2 §4.1, MCPRE-425) vectors.

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::RequestSignature;

use super::material::client_key;
use super::material::edit_signature_input;
use super::material::post;
use super::material::sign_as_client;
use super::material::SignatureInputEdit;
use super::material::CLIENT_KEY_ID;
use super::material::CREATED;
use super::material::EXPIRES;
use super::material::READ_CALL;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

fn request_fixture(name: &str, expected: &str, request: &HttpRequest) -> Fixture {
    Vector {
        name,
        kind: Kind::Request,
        expected,
    }
    .for_request(request)
}

/// A request carrying `Mcp-Method: <method_header>` and `Mcp-Name: read`, signed with the
/// profile's own signer over the read call.
fn signed_with_method_header(method_header: &str) -> HttpRequest {
    let mut request = post(
        &[("Mcp-Method", method_header), ("Mcp-Name", "read")],
        READ_CALL,
    );
    sign_as_client(&mut request, "vec-nonce-mcp");
    request
}

/// h31–h33 check header integrity under the default policy: h31 covered-and-matching
/// positive; h32 present-but-uncovered negative; h33 header/body method mismatch negative.
pub(super) fn mcp_header_fixtures() -> Vec<Fixture> {
    let covered = signed_with_method_header("tools/call");

    // h32 — the header rides on the wire but was dropped from the covered set:
    //       an unsigned method claim attached to a signed request.
    let uncovered = edit_signature_input(&covered, SignatureInputEdit::DropMcpMethod);

    // h33 — the covered header says tools/list, the covered body says tools/call.
    //       The signature is VALID: this is the signer stating two different
    //       methods, and the verifier refuses rather than picking one.
    let diverged = signed_with_method_header("tools/list");

    vec![
        request_fixture("h31_mcp_headers_covered_valid", "verify_ok", &covered),
        request_fixture(
            "h32_mcp_method_present_but_uncovered",
            "mcp-re.missing_envelope",
            &uncovered,
        ),
        request_fixture(
            "h33_mcp_method_body_divergence",
            "mcp-re.malformed_envelope",
            &diverged,
        ),
    ]
}

/// A request signed as given: the contract headers the caller states are the ones that
/// ride, with none derived on its behalf.
fn signed_as_given(headers: &[(&str, &str)], body: &[u8], nonce: &str) -> HttpRequest {
    let mut request = post(headers, body);
    mcp_re_http_profile::sign::sign_request_as_given(
        &mut request,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce,
        },
    )
    .expect("signing succeeds");
    request
}

/// h38–h41 check the full §4.1 contract — required-header presence, supported-version
/// policy, and header/body agreement — under a strict 2026-07-28 transport policy. The
/// runner replays them with that policy attached.
pub(super) fn transport_contract_fixtures() -> Vec<Fixture> {
    let contract_vector = |name: &str, expected: &str, request: &HttpRequest| {
        Vector {
            name,
            kind: Kind::TransportRequest,
            expected,
        }
        .for_request(request)
    };
    let initialize: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;

    // h38 — fully conforming under the strict contract.
    let conforming = signed_as_given(
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "read"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        READ_CALL,
        "vec-nonce-tx-ok",
    );
    // h39 — a required header absent (no Mcp-Method) under the strict contract.
    let missing = signed_as_given(
        &[("MCP-Protocol-Version", "2026-07-28")],
        initialize,
        "vec-nonce-tx-miss",
    );
    // h40 — an unsupported protocol version (a client's claim is not consent).
    let bad_version = signed_as_given(
        &[
            ("Mcp-Method", "initialize"),
            ("MCP-Protocol-Version", "1999-01-01"),
        ],
        initialize,
        "vec-nonce-tx-ver",
    );
    // h41 — Mcp-Name disagreeing with params.name (the routing header naming a
    //       different tool than the signed body invokes).
    let wrong_name = signed_as_given(
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "delete"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        READ_CALL,
        "vec-nonce-tx-name",
    );

    vec![
        contract_vector("h38_transport_contract_valid", "verify_ok", &conforming),
        contract_vector(
            "h39_transport_required_header_absent",
            "mcp-re.missing_envelope",
            &missing,
        ),
        contract_vector(
            "h40_transport_unsupported_version",
            "mcp-re.unsupported_version",
            &bad_version,
        ),
        contract_vector(
            "h41_transport_mcp_name_divergence",
            "mcp-re.malformed_envelope",
            &wrong_name,
        ),
    ]
}
