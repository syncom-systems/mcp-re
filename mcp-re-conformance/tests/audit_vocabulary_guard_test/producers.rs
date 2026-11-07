//! The carriers outside Core: each keeps no `mcp-re.*` literal in its production half, and
//! each Core projection is where that producer's verdicts are decided.

use super::source::Source;

/// Each carrier file as `(runfile env key, the producer it names)`.
const CARRIERS: &[(&str, &str)] = &[
    ("MCP_RE_PROFILE_SRC_ERROR", "HttpProfileError"),
    (
        "MCP_RE_PROFILE_SRC_PROJECTION",
        "the HttpProfileError projection",
    ),
    ("MCP_RE_PROXY_SRC_DISPATCH", "ProxyDispatchError"),
    (
        "MCP_RE_PROXY_SRC_DISPATCH_PROJECTION",
        "the ProxyDispatchError projection",
    ),
    (
        "MCP_RE_CLIENT_CORE_SRC_BINDING_REFUSAL",
        "BindingSpecRefusal",
    ),
    (
        "MCP_RE_CLIENT_CORE_SRC_PROJECTION",
        "the BindingSpecRefusal projection",
    ),
];

/// One Core projection: where its producer's verdicts are decided.
struct Projection {
    env_key: &'static str,
    signature: &'static str,
    who: &'static str,
}

const PROJECTIONS: &[Projection] = &[
    Projection {
        env_key: "MCP_RE_PROFILE_SRC_PROJECTION",
        signature: "impl From<&HttpProfileError> for McpReError",
        who: "the carrier",
    },
    Projection {
        env_key: "MCP_RE_CLIENT_CORE_SRC_PROJECTION",
        signature: "impl From<&BindingSpecRefusal> for McpReError",
        who: "the client seam",
    },
];

/// No carrier's production half holds an `mcp-re.*` literal.
pub(super) fn assert_no_carrier_mints_a_token() {
    for (env_key, who) in CARRIERS {
        let minted = Source::runfile(env_key).production_literals();
        assert!(
            minted.is_empty(),
            "{who} mints its own mcp-re.* token(s) {minted:?} instead of naming a Core              verdict and deriving the token from it. Exactly one file decides what these              strings say (mcp-re-core/src/error.rs); a second table is the parallel              namespace ADR-MCPRE-066 Slice 2 removed."
        );
    }
}

/// Each projection is present in the file scanned, and none has a wildcard arm.
pub(super) fn assert_projections_decide_the_verdicts() {
    for Projection {
        env_key,
        signature,
        who,
    } in PROJECTIONS
    {
        let projection = Source::runfile(env_key);
        assert!(
            projection.contains(signature),
            "{who}'s Core projection is not where this guard is looking"
        );
        assert!(
            !projection.contains("_ =>"),
            "{who}'s Core projection has a wildcard arm — a new failure would inherit a              verdict instead of naming one"
        );
    }
}
