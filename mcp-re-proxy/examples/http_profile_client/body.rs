// SPDX-License-Identifier: Apache-2.0
//! Readings of a verified response body: success or signed rejection, and what it says.

use serde_json::Value;

/// `true` when the verified body is a JSON-RPC error (a signed rejection receipt),
/// not a success `result`.
pub fn is_error_body(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .is_some()
}

/// The frozen `mcp-re.*` wire code from an error body, if present.
pub fn body_wire_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .pointer("/error/data/mcp_re_error/wire_code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Strip the proxy-owned top-level `_meta` (response evidence block) from a
/// verified body and render the MCP `result` for display.
pub fn mcp_result(body: &[u8]) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v
            .get("result")
            .map(|r| r.to_string())
            .unwrap_or_else(|| v.to_string()),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}
