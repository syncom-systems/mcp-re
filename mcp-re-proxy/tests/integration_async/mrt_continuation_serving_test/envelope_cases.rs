// SPDX-License-Identifier: Apache-2.0
//! The response envelope: what is refused before it is signed, and what is still served.

use super::*;

/// **D2 + D5.** An unparseable backend body is refused, on a deployment with NO
/// continuation store.
///
/// The store posture is the entire point of the test. Until ruling D2, the only
/// unconditional inspection of a reply was a `resultType` classifier that returned
/// `None` for a body that was not JSON — "not this check's business" — and every real
/// envelope check lived inside the open-leg recorder, which returns early with no store
/// wired. So MCP-RE signed unparseable bytes, retained them, recorded
/// `mcp-re.response.signed`, and the client's own verifier then rejected a message the
/// enforcement boundary had vouched for.
///
/// Running this WITHOUT a store is what makes the mutation faithful: with one wired, the
/// recorder catches the body and the test would pass while proving nothing about the
/// validator.
#[tokio::test]
async fn an_unparseable_backend_body_is_refused_even_with_no_continuation_store() {
    for garbage in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"jsonrpc\":\"2.0\","[..],
        &b"<html>502 Bad Gateway</html>"[..],
    ] {
        let proxy = replica_without_store(replying_with(garbage));
        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: UPSTREAM_INVALID,
                why: &format!("{garbage:?} was signed as a response"),
            },
        );
        assert_execution(&served, POSSIBLY_EXECUTED, &format!("{garbage:?}"));
    }
}

/// **D5.** The JSON-RPC envelope rules, enforced end to end on the serving path.
///
/// Each body below is well-formed JSON and would have been signed and served before this
/// ruling. None of them is a legal response to the outstanding request, and MCP-RE is the
/// component with the authority to say so — the client can only refuse afterwards, having
/// already been told the boundary vouched for it.
#[tokio::test]
async fn an_illegal_json_rpc_envelope_is_refused_before_it_is_signed() {
    // The outstanding request is `OPEN_BODY`, whose id is 1.
    for (label, body) in [
        (
            "wrong id",
            r#"{"jsonrpc":"2.0","id":99,"result":{"ok":true}}"#,
        ),
        (
            "id type differs",
            r#"{"jsonrpc":"2.0","id":"1","result":{"ok":true}}"#,
        ),
        ("id absent", r#"{"jsonrpc":"2.0","result":{"ok":true}}"#),
        (
            "both members",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1,"message":"x"}}"#,
        ),
        ("neither member", r#"{"jsonrpc":"2.0","id":1}"#),
        ("jsonrpc absent", r#"{"id":1,"result":{"ok":true}}"#),
        (
            "jsonrpc wrong",
            r#"{"jsonrpc":"1.0","id":1,"result":{"ok":true}}"#,
        ),
        (
            "error member malformed",
            r#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#,
        ),
    ] {
        let proxy = replica_without_store(replying_with(body.as_bytes()));
        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: UPSTREAM_INVALID,
                why: &format!("{label} was accepted"),
            },
        );
    }
}

/// The mirror, so the test above cannot pass by refusing everything: a LEGAL envelope
/// through the same store-less proxy is still served, and a JSON-RPC error is one of them.
///
/// The second case is the one worth stating. A JSON-RPC error is a valid terminal protocol
/// response — not a malformed message and not a transport failure — and collapsing it into
/// either would end the exchange on the wrong fact.
#[tokio::test]
async fn a_legal_envelope_is_still_served_and_a_json_rpc_error_is_one() {
    for (label, body) in [
        (
            "ordinary result",
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ok":true}}"#,
        ),
        (
            "json-rpc error",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"the tool refused"}}"#,
        ),
        (
            "result with no resultType (pre-2026-07-28 server)",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        ),
    ] {
        let proxy = replica_without_store(replying_with(body.as_bytes()));
        let served = serve_open_call(&proxy).await;

        assert_status(&served, 200, &format!("{label} was refused"));
    }
}

/// **R8-C053 / C054.** A body that is not a legal JSON-RPC request never reaches the
/// backend, and never earns a signed acknowledgement.
///
/// Broken implementation this must catch: the one in the tree before the validator was
/// wired — the only member ever read on the request side was `id`, by `outstanding_id`,
/// and its ABSENCE was read as "notification". So an object carrying nothing but an
/// evidence block, or a document that is simultaneously a request and a response, or one
/// whose `jsonrpc` is not `"2.0"`, was forwarded to the inner server and then acknowledged
/// with a delegated-signed 202 asserting the enforcement boundary had accepted an MCP
/// message. A `null` id was folded into the notification arm for the same reason, and the
/// two are answered differently — one with a bound signed reply, the other with a
/// bodyless 202.
///
/// Asserted on the BACKEND COUNT, which is the mechanism: every one of these bodies would
/// have produced a plausible-looking response from the proxy either way, and only the
/// dispatch count distinguishes "refused" from "refused after running it".
#[tokio::test]
async fn a_body_that_is_not_a_json_rpc_request_never_reaches_the_backend() {
    let illegal: &[(&str, &[u8])] = &[
        (
            "no method member",
            br#"{"jsonrpc":"2.0","id":1,"params":{}}"#,
        ),
        ("no jsonrpc member", br#"{"id":1,"method":"tools/call"}"#),
        (
            "wrong jsonrpc version",
            br#"{"jsonrpc":"1.0","id":1,"method":"tools/call"}"#,
        ),
        (
            "also a response",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}"#,
        ),
        (
            "scalar params",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":7}"#,
        ),
        (
            "null id folded into a notification",
            br#"{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}"#,
        ),
        ("bare evidence carrier", br#"{"greeting":"hello"}"#),
    ];

    for (name, body) in illegal {
        envelopes::assert_illegal_body_refused(name, body).await;
    }
}

/// The non-vacuity control for the validator: the two LEGAL request shapes still pass, and
/// still reach their own terminals.
///
/// Without this, a validator that refused every body would satisfy the test above.
#[tokio::test]
async fn the_two_legal_request_shapes_still_reach_their_terminals() {
    let calls = counter();
    let bodied = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    );
    assert_eq!(serve_open_call(&bodied).await.status, 200);
    assert_eq!(invocations(&calls), 1);

    let notes = notification_proxy(DispatchedOutcome::Replied(Vec::new()));
    assert_eq!(serve_notification(&notes).await.status, 202);
}
