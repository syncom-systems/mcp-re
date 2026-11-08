// SPDX-License-Identifier: Apache-2.0
//! Rebuilding what the LOCAL client sees from what the remote server provably said: a plain
//! JSON-RPC reply from a verified signed body, and a plain JSON-RPC error from a verified
//! rejection receipt. Nothing here verifies; both inputs have already passed verification.

use mcp_re_client_core::ExecutionContract;
use mcp_re_client_core::HttpProfileError;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use crate::transport::ProxyError;

/// Convert a VERIFIED delegated rejection receipt to a PLAIN JSON-RPC error for the
/// local client. The proxy has already verified the receipt's signature, so this is a
/// provable denial, not a guess.
///
/// Transparency is about the CARRIER, not about withholding what the server said: the
/// local client still speaks ordinary JSON-RPC and never emits, parses or negotiates an
/// RFC 9421 field. The server's frozen wire code and its ADR-MCPRE-058 §10 execution /
/// retry contract ride in the ordinary `error.data` member, because the party that
/// decides whether to retry is the local agent and nothing else it can see distinguishes
/// a refusal that ran nothing from a post-dispatch failure whose side effect a retry
/// performs twice. A fixed generic error told it neither, so it re-invoked.
///
/// Only members the receipt actually carried are emitted. An absent `execution_status`
/// is a receipt that said nothing, and inventing `not_executed` for it would collapse
/// "unknown whether it ran" into "it did not run" at the one place that matters.
pub(crate) fn plain_error_from_rejection(
    id: Option<&Value>,
    wire_code: Option<&str>,
    execution: &ExecutionContract,
) -> Value {
    let mut mcp_re_error = serde_json::Map::new();
    if let Some(wire_code) = wire_code {
        mcp_re_error.insert("wire_code".into(), json!(wire_code));
    }
    for (name, value) in [
        ("execution_status", &execution.execution_status),
        ("retry_safety", &execution.retry_safety),
        ("continuation_status", &execution.continuation_status),
        ("retention_status", &execution.retention_status),
    ] {
        if let Some(value) = value {
            mcp_re_error.insert(name.into(), json!(value));
        }
    }
    // Class B: assembled as a map. Writing back through `error["data"]` panics unless
    // `error` is an object, which is a fact about a literal rather than anything the
    // assignment establishes.
    let mut error = serde_json::Map::new();
    error.insert(
        "code".to_owned(),
        json!(mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE),
    );
    error.insert(
        "message".to_owned(),
        json!("request rejected by the MCP-RE server"),
    );
    if !mcp_re_error.is_empty() {
        error.insert(
            "data".to_owned(),
            json!({ "mcp_re_error": Value::Object(mcp_re_error) }),
        );
    }
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        envelope.insert("id".to_owned(), id.clone());
    }
    envelope.insert("error".to_owned(), Value::Object(error));
    Value::Object(envelope)
}

/// Rebuild a PLAIN MCP response from a verified signed response: strip the
/// proxy-owned top-level `_meta` (the RFC 9421 response evidence block) from the
/// body, returning ordinary JSON-RPC.
/// The `id` is the one the PROXY signed, not the one the server echoed back: the reply
/// belongs to the local client's outstanding call, and reading it from the response
/// body would let a server address its answer to a different one.
///
/// A JSON-RPC `error` member is carried through, minus any `error.data.mcp_re_error`
/// the backend wrote: that member is the proxy's own, written only from a verified
/// rejection receipt, so it is removed rather than the reply refused. The serving path signs every bodied
/// backend reply with HTTP 200 — a JSON-RPC error from an MCP backend rides in that
/// 200 body — so rebuilding the reply from `result` alone reported a failed call as a
/// successful one returning `null`, dropped the reason, and emitted a message that was
/// neither a valid JSON-RPC result nor a valid error.
///
/// A body that is not a single JSON-RPC response object carrying EXACTLY ONE of
/// `result` / `error` fails closed. A signed reply is proof the server said this; it is
/// not proof the server said anything a client can act on, and every other shape — a
/// top-level array, a bare scalar, an empty `{"jsonrpc":"2.0","id":1}` envelope, both
/// members at once — has no reading under which "the call completed with result `null`"
/// is true. Defaulting them to a null result is the same defect as flattening an error
/// reply: a truthful-looking success the server never sent.
///
/// Bytes that are not JSON at all fail the same way, and for the same reason: the bytes
/// that failed to parse are the RESPONSE to an exchange the remote server has already
/// executed. Reporting that as a malformed REQUEST hands the caller a 4xx implying its
/// own message was bad and nothing ran, and a caller that "fixes" its request and
/// retries re-runs a side effect the server already performed.
pub(crate) fn plain_response_from_verified(
    response_body: &[u8],
    request_id: &Value,
) -> Result<Value, ProxyError> {
    let mut object: Value = serde_json::from_slice(response_body).map_err(|_| {
        ProxyError::FailedClosed(HttpProfileError::MalformedEvidence(
            "verified reply is not JSON",
        ))
    })?;
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("_meta");
    }
    let Some(top) = object.as_object_mut() else {
        return Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence("verified reply is not a JSON-RPC object"),
        ));
    };
    top.remove("_meta");
    // A JSON-RPC response has no `method`. Its presence is what makes a permissive
    // union parser pick the REQUEST arm, so a reply carrying both a legal `result` and a
    // `method` becomes a server->client request the client's session dispatches —
    // sampling, elicitation, roots — over a channel MCP-RE profiles no carrier for, and
    // the call whose id was consumed never resolves. Refused rather than dropped, so all
    // three clients say the same thing about the same bytes.
    if top.contains_key("method") {
        return Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries a top-level method; a JSON-RPC response has none",
            ),
        ));
    }
    match (top.get("result"), top.get("error")) {
        (Some(_), Some(_)) => Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries both a result and an error",
            ),
        )),
        (None, None) => Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries neither a result nor an error",
            ),
        )),
        (None, Some(error)) => {
            let mut error = error.clone();
            if let Some(data) = error.get_mut("data").and_then(Value::as_object_mut) {
                data.remove("mcp_re_error");
            }
            Ok(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": error,
            }))
        }
        (Some(result), None) => Ok(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ResponseKind;
    use mcp_re_client_core::classify_result;
    use mcp_re_client_core::continuation_state_of;
    use mcp_re_client_core::ResultClass;

    /// A JSON-RPC error rides in the same HTTP 200 body an ordinary result does, so
    /// rebuilding the plain reply from `result` alone reported a failed call as a
    /// success returning null and dropped the reason with it.
    #[test]
    fn a_json_rpc_error_reply_is_carried_through_not_flattened_to_a_null_result() {
        let body = br#"{"jsonrpc":"2.0","id":"srv-1","error":{"code":-32601,"message":"method not found"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");

        assert_eq!(plain["error"]["code"], -32601);
        assert_eq!(plain["error"]["message"], "method not found");
        assert!(
            plain.get("result").is_none(),
            "an error reply must not also carry a result member"
        );
    }

    /// Carrying the error through is only half of it: the classification the local
    /// client reads must say the call failed. `classify_result` inspects `result`, and
    /// an error reply has none — an absent `result` classifies as Terminal, which is
    /// the success label. The signature verifies either way, so nothing downstream can
    /// recover the difference once the header has been written.
    #[test]
    fn a_verified_error_reply_is_classified_as_a_failed_call_not_a_success() {
        let body = br#"{"jsonrpc":"2.0","id":"srv-1","error":{"code":-32601,"message":"method not found"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");

        // The selection the serving path makes, on the reply it actually holds.
        let kind = match plain
            .get("error")
            .map(|e| e.get("code").and_then(Value::as_i64))
        {
            Some(code) => ResponseKind::CallFailed { code },
            None => match classify_result(plain.get("result")) {
                ResultClass::Terminal => ResponseKind::Success,
                _ => unreachable!("this fixture carries an error member"),
            },
        };

        assert!(
            matches!(kind, ResponseKind::CallFailed { code: Some(-32601) }),
            "an error reply must classify as CallFailed carrying the server's code, got {kind:?}"
        );
        assert!(
            !matches!(kind, ResponseKind::Success),
            "a failed call must never be announced to the local client as a success"
        );
    }

    /// The id belongs to the local client's outstanding call. Taking it from the
    /// response body would let a server address its answer to a different one.
    #[test]
    fn the_reply_carries_the_id_the_proxy_signed_not_the_one_the_server_echoed() {
        let body = br#"{"jsonrpc":"2.0","id":"server-chosen","result":{"ok":true}}"#;
        let plain = plain_response_from_verified(body, &json!("req-7")).expect("rebuild");
        assert_eq!(plain["id"], "req-7");
        assert_eq!(plain["result"]["ok"], true);
    }

    /// The proxy-owned response evidence block is stripped from both positions.
    #[test]
    fn the_proxy_owned_meta_is_stripped_from_the_plain_reply() {
        let body =
            br#"{"jsonrpc":"2.0","id":"s","_meta":{"a":1},"result":{"_meta":{"b":2},"ok":true}}"#;
        let plain = plain_response_from_verified(body, &json!(1)).expect("rebuild");
        assert!(plain.get("_meta").is_none());
        assert!(plain["result"].get("_meta").is_none());
        assert_eq!(plain["result"]["ok"], true);
    }

    /// The classification the success arm makes before handing a reply over. A
    /// non-terminal elicitation reported as `Success` is how an approval nobody gave
    /// reaches an application as a finished tool result.
    #[test]
    fn an_input_required_reply_does_not_classify_as_terminal() {
        // The discriminator VALUE comes from the profile's own constant, never a
        // literal: an open-coded copy is one more thing to drift, and the gate that
        // enforces that is exactly why this reads the way it does.
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"s","result":{{"resultType":"{}","requestState":"st-1"}}}}"#,
            mcp_re_client_core::INPUT_REQUIRED_RESULT_TYPE
        );
        let body = body.as_bytes();
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");
        assert_eq!(
            classify_result(plain.get("result")),
            ResultClass::InputRequired
        );
        assert_eq!(
            continuation_state_of(plain.get("result")).expect("state"),
            Some("st-1".to_owned())
        );

        let terminal = br#"{"jsonrpc":"2.0","id":"s","result":{"ok":true}}"#;
        let plain = plain_response_from_verified(terminal, &json!("req-1")).expect("rebuild");
        assert_eq!(classify_result(plain.get("result")), ResultClass::Terminal);
    }

    /// The shapes next to the JSON-RPC-error one. Each used to fall through to
    /// `result: null` and classify Terminal, so a signed reply that is not a JSON-RPC
    /// response at all reached the local client as a completed tool call — the same
    /// defect as flattening an error reply, on its neighbours.
    #[test]
    fn a_reply_that_is_not_a_json_rpc_response_fails_closed() {
        for body in [
            // An envelope with neither member.
            br#"{"jsonrpc":"2.0","id":1}"#.as_slice(),
            // A batch array, a bare scalar, a bare string.
            br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#.as_slice(),
            br#"7"#.as_slice(),
            br#""ok""#.as_slice(),
            // Both members at once: no reading of this says the call completed.
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1}}"#.as_slice(),
            // A legal `result` plus a top-level `method`. A permissive union parser —
            // which is what both SDKs hand this to — reads it as a server->client
            // REQUEST and dispatches sampling / elicitation / roots on the peer's
            // params, while the call whose id it consumed never resolves.
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"method":"sampling/createMessage","params":{"x":1}}"#.as_slice(),
        ] {
            let outcome = plain_response_from_verified(body, &json!("req-1"));
            assert!(
                matches!(outcome, Err(ProxyError::FailedClosed(_))),
                "{} must not be delivered as a success",
                String::from_utf8_lossy(body),
            );
        }
    }

    /// And the shape that IS a response still rebuilds, `_meta` stripped — the guard
    /// above refuses malformed evidence, not an ordinary empty result.
    #[test]
    fn an_ordinary_result_still_rebuilds() {
        let body = br#"{"jsonrpc":"2.0","id":"s","result":{}}"#;
        let plain = plain_response_from_verified(body, &json!(2)).expect("rebuild");
        assert_eq!(plain["id"], 2);
        assert_eq!(plain["result"], json!({}));
    }

    /// Bytes that are not JSON at all are a RESPONSE failure, not a caller error.
    ///
    /// Mapping them to `MalformedRequest` renders as HTTP 400 at the ambassador, whose
    /// own comment justifies that status with "raised entirely locally, before anything
    /// is signed or sent" — untrue here: the remote server has already executed the
    /// exchange. A caller that "fixes" its request and retries a 400 re-runs the side
    /// effect.
    #[test]
    fn an_unparseable_verified_reply_is_a_verification_failure_not_a_bad_request() {
        let outcome = plain_response_from_verified(b"not json at all", &json!("req-1"));
        assert!(
            matches!(outcome, Err(ProxyError::FailedClosed(_))),
            "an unreadable RESPONSE must not be reported as a malformed REQUEST, got {outcome:?}",
        );
        assert!(
            !matches!(outcome, Err(ProxyError::MalformedRequest)),
            "400 implies the request was never executed",
        );
    }

    /// The ADR-MCPRE-058 §10 contract must reach the party that decides whether to
    /// retry. A fixed generic error told the local agent nothing, so a post-dispatch
    /// 503 read as an ordinary outage and the retry re-executed the tool call.
    #[test]
    fn a_verified_rejection_carries_its_execution_contract_to_the_local_client() {
        let execution = ExecutionContract {
            execution_status: Some("possibly_executed".into()),
            retry_safety: Some("unsafe_without_reconciliation".into()),
            continuation_status: Some("consumed".into()),
            retention_status: None,
        };
        let plain = plain_error_from_rejection(
            Some(&json!("req-1")),
            Some("mcp-re.inner_dispatch_indeterminate"),
            &execution,
        );
        let data = &plain["error"]["data"]["mcp_re_error"];
        assert_eq!(data["wire_code"], "mcp-re.inner_dispatch_indeterminate");
        assert_eq!(data["execution_status"], "possibly_executed");
        assert_eq!(data["retry_safety"], "unsafe_without_reconciliation");
        assert_eq!(data["continuation_status"], "consumed");
        assert!(
            data.get("retention_status").is_none(),
            "a member the receipt did not carry must not be invented"
        );
        // The plain reply is still ordinary JSON-RPC: the local client parses an error,
        // not an MCP-RE carrier field.
        assert_eq!(plain["jsonrpc"], "2.0");
        assert_eq!(plain["id"], "req-1");
        assert_eq!(
            plain["error"]["code"],
            mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE
        );
    }

    /// A receipt that stated nothing must not grow a disposition on the way through.
    /// Emitting `not_executed` for an absent `execution_status` would turn "unknown
    /// whether it ran" into "it did not run" at the one place that decides.
    #[test]
    fn an_unstated_contract_produces_no_invented_disposition() {
        let plain = plain_error_from_rejection(
            Some(&json!(1)),
            Some("mcp-re.invalid_signature"),
            &ExecutionContract::default(),
        );
        let data = &plain["error"]["data"]["mcp_re_error"];
        assert_eq!(data["wire_code"], "mcp-re.invalid_signature");
        assert!(data.get("execution_status").is_none());
        assert!(data.get("retry_safety").is_none());

        // And a receipt with no wire code either emits no `data` at all rather than an
        // empty object that reads as a statement.
        let bare = plain_error_from_rejection(Some(&json!(1)), None, &ExecutionContract::default());
        assert!(bare["error"].get("data").is_none());
    }

    /// MCP 2026-07-28 closes the `resultType` set; an unknown one is never resolved
    /// to terminal, and the success arm turns it into a fail-closed error.
    #[test]
    fn an_unrecognized_result_type_is_never_terminal() {
        let body = br#"{"jsonrpc":"2.0","id":"s","result":{"resultType":"something_new"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");
        assert_eq!(
            classify_result(plain.get("result")),
            ResultClass::Unrecognized
        );
    }

    /// A backend error cannot write the proxy's own `error.data.mcp_re_error` member:
    /// that member is only ever built from a verified rejection receipt.
    #[test]
    fn a_backend_error_cannot_speak_in_the_boundary_mcp_re_error_member() {
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"m","data":{"mcp_re_error":{"execution_status":"not_executed","wire_code":"mcp-re.expired_request"},"detail":"kept"}}}"#;
        let plain = plain_response_from_verified(body, &json!(1)).expect("rebuild");
        assert!(plain["error"]["data"].get("mcp_re_error").is_none());
        assert_eq!(plain["error"]["data"]["detail"], "kept");
        assert_eq!(plain["error"]["code"], -32000);
        assert_eq!(plain["error"]["message"], "m");
    }
}
