// SPDX-License-Identifier: Apache-2.0
//! The request-side envelope check: a body that is not a legal MCP message is refused
//! before the backend, at no cost to the replay slot.

use std::sync::Arc;

use super::harness::bare_proxy;
use super::harness::ready_signer;
use super::harness::served_of;
use super::harness::signed_request;
use super::harness::NOW;
use super::harness::OPEN_BODY;
use super::harness::RESPONSE_SIG_TTL;
use super::inners::counter;
use super::inners::counting_inner;
use super::inners::invocations;
use super::replies::assert_retry_posture;
use super::replies::assert_status;
use super::replies::wire_code_of;

/// One body the PEP must refuse before it reaches the backend, with the replay slot
/// still free afterwards.
pub(super) async fn assert_illegal_body_refused(name: &str, body: &[u8]) {
    let calls = counter();
    let proxy = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    );
    let nonce = format!("nonce-R8-env-{name}");

    let (req, _e) = signed_request(&nonce, body, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(
        invocations(&calls),
        0,
        "{name}: a body that is not an MCP message must not be dispatched"
    );
    // Refused before dispatch either way, never acknowledged as a notification and never
    // served as a success. A body the mandatory transport contract cannot be satisfied by
    // (no method, or a target-naming method with no name) is refused by the verifier (403);
    // the rest are refused as malformed MCP messages (400).
    assert!(
        matches!(served.status, 400 | 403),
        "{name}: {}",
        served.status
    );
    let code = wire_code_of(&served.body);
    assert!(
        matches!(
            code.as_str(),
            "mcp-re.malformed_envelope" | "mcp-re.missing_envelope"
        ),
        "{name}: {code}"
    );
    // Refused before admission: nothing ran and nothing was spent.
    assert_retry_posture(&served.body, None);

    // The refusal is FREE, and the replay slot proves it: the same nonce is still
    // admissible for a well-formed request. Without this the test would pass against
    // an implementation that refused correctly but had already burned the nonce.
    let (retry, _e) = signed_request(&nonce, OPEN_BODY, None);
    assert_status(
        &proxy.handle(served_of(&retry), NOW).await,
        200,
        &format!("{name}: the refused envelope must not have spent the replay slot"),
    );
    assert_eq!(invocations(&calls), 1);
}
