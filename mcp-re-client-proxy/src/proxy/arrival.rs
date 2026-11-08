// SPDX-License-Identifier: Apache-2.0
//! What `handle` passes between its stages: the reply and the instant it arrived.

use mcp_re_client_core::HttpResponse;

/// A transport reply together with the instant it arrived, which is the clock the reply
/// is judged at.
#[derive(Clone, Copy)]
pub(super) struct Arrival<'a> {
    pub(super) response: &'a HttpResponse,
    pub(super) now_unix: i64,
}
