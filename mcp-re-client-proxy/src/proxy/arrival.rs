// SPDX-License-Identifier: Apache-2.0
//! The two facts `handle` passes between its stages: when a reply arrived, and whether the
//! message it answers named an id.

use mcp_re_client_core::HttpResponse;
use serde_json::Value;

/// A transport reply together with the instant it arrived, which is the clock the reply
/// is judged at.
#[derive(Clone, Copy)]
pub(super) struct Arrival<'a> {
    pub(super) response: &'a HttpResponse,
    pub(super) now_unix: i64,
}

/// The JSON-RPC `id` of a plain message, absent for a NOTIFICATION. Both the signer and
/// the verification path classify on exactly this key's absence, so this is the one place
/// that reads it.
pub(super) fn request_id(plain_request: &Value) -> Option<&Value> {
    plain_request.get("id")
}
