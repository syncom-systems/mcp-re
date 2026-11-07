// SPDX-License-Identifier: Apache-2.0
//! Reading and asserting on the facts a signed rejection states about the exchange.
//!
//! Read from the BODY rather than inferred from the status code, deliberately: the whole
//! point of ADR-MCPRE-058 §10 ruling D1 is that a status code cannot answer whether the
//! action ran, and a test asserting only on status would pass against the behaviour the
//! ruling replaced.

use mcp_re_proxy::async_serve::ServedHttpResponse;

/// The wire codes and execution claims the tests pin.
pub(super) const BINDING_FAILED: &str = "mcp-re.continuation_binding_failed";
pub(super) const RETENTION_UNAVAILABLE: &str = "mcp-re.evidence_retention_unavailable";
pub(super) const CACHE_UNAVAILABLE: &str = "mcp-re.replay_cache_unavailable";
pub(super) const UPSTREAM_INVALID: &str = "mcp-re.upstream_response_invalid";
pub(super) const INNER_PLANE_UNAVAILABLE: &str = "mcp-re.inner_plane_unavailable";
pub(super) const INDETERMINATE: &str = "mcp-re.inner_dispatch_indeterminate";
pub(super) const POSSIBLY_EXECUTED: &str = "possibly_executed";

/// A member of the `mcp_re_error` object a rejection carries.
#[derive(Clone, Copy)]
enum Field {
    WireCode,
    RetrySafety,
    ExecutionStatus,
    ContinuationStatus,
}

impl Field {
    fn pointer(self) -> &'static str {
        match self {
            Field::WireCode => "/error/data/mcp_re_error/wire_code",
            Field::RetrySafety => "/error/data/mcp_re_error/retry_safety",
            Field::ExecutionStatus => "/error/data/mcp_re_error/execution_status",
            Field::ContinuationStatus => "/error/data/mcp_re_error/continuation_status",
        }
    }
}

fn field_of(body: &[u8], field: Field) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer(field.pointer())
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        })
}

pub(super) fn wire_code_of(body: &[u8]) -> String {
    field_of(body, Field::WireCode).unwrap_or_default()
}

pub(super) fn execution_status_of(body: &[u8]) -> Option<String> {
    field_of(body, Field::ExecutionStatus)
}

/// The `requestState` a successful reply carries in its result, if any.
pub(super) fn request_state_of(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.pointer("/result/requestState")?
        .as_str()
        .map(str::to_owned)
}

/// The `resultType` a successful reply carries in its result, if any.
pub(super) fn result_type_of(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.pointer("/result/resultType")?.as_str().map(str::to_owned)
}

/// The refusal a test expects: its status, the wire code naming it, and what the
/// assertion pins.
pub(super) struct Refusal<'a> {
    pub(super) status: u16,
    pub(super) code: &'a str,
    pub(super) why: &'a str,
}

pub(super) fn assert_refused(served: &ServedHttpResponse, expected: Refusal<'_>) {
    assert_eq!(
        (served.status, wire_code_of(&served.body).as_str()),
        (expected.status, expected.code),
        "{}",
        expected.why
    );
}

/// Assert the status of a reply that is not a refusal.
pub(super) fn assert_status(served: &ServedHttpResponse, status: u16, why: &str) {
    assert_eq!(
        served.status,
        status,
        "{why} (got {})",
        wire_code_of(&served.body)
    );
}

pub(super) fn assert_execution(served: &ServedHttpResponse, expected: &str, why: &str) {
    assert_eq!(
        execution_status_of(&served.body).as_deref(),
        Some(expected),
        "{why}"
    );
}

pub(super) fn assert_not_possibly_executed(served: &ServedHttpResponse, why: &str) {
    assert_ne!(
        execution_status_of(&served.body).as_deref(),
        Some("possibly_executed"),
        "{why}"
    );
}

/// Assert the machine-derived retry posture on a signed refusal body.
///
/// `None` means the refusal states nothing beyond its wire code, which is the correct
/// posture for an ordinary retry-safe failure.
pub(super) fn assert_retry_posture(body: &[u8], expected: Option<&str>) {
    let got = field_of(body, Field::RetrySafety);
    assert_eq!(
        got.as_deref(),
        expected,
        "retry posture in {}",
        String::from_utf8_lossy(body)
    );
}

/// The exchange refused before the backend could run, with the approval it spent gone:
/// neither machine can state this alone — the request machine truthfully says the backend
/// did not run, the continuation machine truthfully says the leg was consumed, and the
/// client needs the pair.
pub(super) fn assert_approval_spent_and_action_unrun(served: &ServedHttpResponse) {
    assert_execution(served, "not_executed", "the action did not run");
    assert_eq!(
        field_of(&served.body, Field::ContinuationStatus).as_deref(),
        Some("consumed"),
        "the approval is gone"
    );
    assert_retry_posture(&served.body, Some("unsafe_without_new_elicitation"));
}

/// An ordinary retry-safe refusal: it states no continuation and no retry posture.
pub(super) fn assert_states_no_continuation_or_retry_posture(served: &ServedHttpResponse) {
    let body = String::from_utf8_lossy(&served.body);
    assert!(
        field_of(&served.body, Field::ContinuationStatus).is_none(),
        "{body}"
    );
    assert!(
        field_of(&served.body, Field::RetrySafety).is_none(),
        "{body}"
    );
}

/// Read the `expires` parameter off a signed response's `signature-input` header.
pub(super) fn advertised_expiry(resp: &ServedHttpResponse) -> i64 {
    let value = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .map(|(_, v)| v.clone())
        .expect("a signed response carries signature-input");
    let after = value
        .split("expires=")
        .nth(1)
        .expect("an expires parameter");
    after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .expect("expires is an integer")
}

/// A refusal that is signed, and carries the inline delegation credential that lets a
/// client verify it.
pub(super) fn assert_signed_with_inline_delegation(served: &ServedHttpResponse) {
    assert!(
        served
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("signature")),
        "a post-dispatch refusal must not degrade to an unsigned body"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&served.body).expect("the refusal body is JSON");
    assert!(
        body.pointer("/_meta/se.syncom~1mcp-re.http.response")
            .and_then(|b| b.get("server_delegation"))
            .is_some(),
        "the inline delegation credential rides with the signed refusal: {body}"
    );
}
