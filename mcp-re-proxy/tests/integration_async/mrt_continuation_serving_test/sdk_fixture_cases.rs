// SPDX-License-Identifier: Apache-2.0
//! The SDK-boundary fixture writers for the same defects.

use super::*;

/// Freeze a delegated-signed exchange whose reply declares itself non-terminal and
/// withholds its `requestState`, so both SDK bindings can prove they REFUSE it.
///
/// A recorded fixture cannot come from the proxy here: a conformant MCP-RE proxy now
/// rejects this body rather than serving it (see the test above), which is the whole
/// point. The malformed reply is therefore signed directly with the same delegated
/// custody the proxy uses — it stands for a non-conformant or hostile server, which
/// is the only place such a reply can now originate.
///
/// Regenerate: `MCP_RE_WRITE_SDK_FIXTURE=1 bazel run //mcp-re-proxy:integration_async_test --
/// mrt_continuation_serving_test::write_malformed_elicitation_sdk_fixture --exact`. Runfiles are symlinks to the
/// source, so the recording under `sdk/fixtures` is rewritten in place.
#[test]
fn write_malformed_elicitation_sdk_fixture() {
    SdkFixture {
        recording: Recording::MalformedElicitation,
        nonce: "nonce-sdk-malformed",
        reply_body: br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#,
        comment: "A delegated-signed reply that declares itself non-terminal and withholds \
                  its requestState. Genuine evidence with a malformed body: both SDK \
                  bindings must REFUSE it, never report it as a terminal result. \
                  Writer: write_malformed_elicitation_sdk_fixture \
                  (mrt_continuation_serving_test) with MCP_RE_WRITE_SDK_FIXTURE=1",
    }
    .write_or_gate();
}

/// Freeze a delegated-signed reply whose `resultType` is outside the set MCP
/// 2026-07-28 defines (MCPRE-495), so both SDK bindings can prove they refuse it
/// rather than reading it as a completed call.
///
/// Defense in depth: a conformant proxy will not sign such a reply at all, so this
/// stands for a non-conformant or hostile server — the only place one can now come
/// from. The evidence is genuine; only the result type is unreadable.
///
/// Regenerate: `MCP_RE_WRITE_SDK_FIXTURE=1 bazel run //mcp-re-proxy:integration_async_test --
/// mrt_continuation_serving_test::write_unrecognized_result_type_sdk_fixture --exact`. Runfiles are symlinks to the
/// source, so the recording under `sdk/fixtures` is rewritten in place.
#[test]
fn write_unrecognized_result_type_sdk_fixture() {
    SdkFixture {
        recording: Recording::UnrecognizedResultType,
        nonce: "nonce-sdk-unrecognized",
        reply_body: br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#,
        comment: "A delegated-signed reply carrying a resultType outside the set MCP \
                  2026-07-28 defines. Genuine evidence this reader cannot classify: both SDK \
                  bindings must REFUSE it, never report it as a terminal result. \
                  Writer: write_unrecognized_result_type_sdk_fixture \
                  (mrt_continuation_serving_test) with MCP_RE_WRITE_SDK_FIXTURE=1",
    }
    .write_or_gate();
}
