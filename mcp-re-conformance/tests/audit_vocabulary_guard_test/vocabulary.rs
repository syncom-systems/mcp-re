//! The audit-event vocabulary the guard pins: the five exact allowlists, and the audit
//! source read through the `event_type` constants the slices name.

use std::collections::BTreeSet;

use super::source::Source;

/// The exact, exhaustive success/lifecycle allowlist (ADR-MCPS-035 §3). These are
/// the ONLY audit events the frozen error taxonomy cannot express; the audit
/// module's `SUCCESS_EVENT_TYPES` must equal this set, and nothing else may be
/// minted without an ADR.
pub(super) const EXPECTED_SUCCESS_EVENTS: &[&str] =
    &["mcp-re.request.accepted", "mcp-re.response.signed"];

/// The two rejection `event_type`s. Each carries a frozen `wire_code()` token in
/// `reason`; neither is itself a `wire_code()` token.
pub(super) const EXPECTED_REJECTION_EVENTS: &[&str] =
    &["mcp-re.request.rejected", "mcp-re.response.rejected"];

/// The three delegated-key lifecycle `event_type`s — the third audit category,
/// authorized by ADR-MCPRE-052 §7. Not verdicts (no `reason`); emitted by the
/// custody layer. Nothing else may join this set without an ADR.
pub(super) const EXPECTED_KEY_LIFECYCLE_EVENTS: &[&str] = &[
    "mcp-re.delegated_key.issued",
    "mcp-re.delegated_key.rotated",
    "mcp-re.delegated_key.retired",
];

/// The one execution `event_type` — the fourth audit category, authorized by ADR-MCPRE-070 D1
/// as a documented, versioned extension (vocabulary revision 2). It says the dispatch of an
/// admitted exchange was committed to: not a success event, not a verdict (no `reason`), and
/// never on the best-effort stream. Nothing else may join this set without an ADR.
const EXPECTED_EXECUTION_EVENTS: &[&str] = &["mcp-re.execution.intent"];

/// The one accounting `event_type` — the fifth audit category, authorized by ADR-MCPRE-070 D2
/// and Q3 as a documented, versioned extension (vocabulary revision 3). A bounded, run- and
/// interval-attributed aggregate count: not a success event, not a verdict (no `reason`), no
/// actor. Nothing else may join this set without an ADR.
const EXPECTED_ACCOUNTING_EVENTS: &[&str] = &["mcp-re.audit.accounting"];

/// Every fixed audit `event_type`, across the five categories.
pub(super) fn all_event_types() -> impl Iterator<Item = &'static str> {
    [
        EXPECTED_SUCCESS_EVENTS,
        EXPECTED_REJECTION_EVENTS,
        EXPECTED_KEY_LIFECYCLE_EVENTS,
        EXPECTED_EXECUTION_EVENTS,
        EXPECTED_ACCOUNTING_EVENTS,
    ]
    .into_iter()
    .flat_map(|group| group.iter().copied())
}

/// An allowlist as an owned set, comparable with what `audit.rs` declares.
pub(super) fn token_set(allowlist: &[&str]) -> BTreeSet<String> {
    allowlist.iter().map(|token| token.to_string()).collect()
}

/// `mcp-re-core/src/audit.rs` as read from disk, with its `event_type` constants resolved.
pub(super) struct AuditSource {
    source: Source,
    consts: Vec<(String, String)>,
}

impl AuditSource {
    pub(super) fn load() -> Self {
        let source = Source::runfile("MCP_RE_CORE_SRC_AUDIT");
        let consts = source.event_type_consts();
        Self { source, consts }
    }

    /// The tokens the `pub const <slice>` declaration lists, constants resolved.
    fn declared(&self, slice: &str) -> BTreeSet<String> {
        self.source.slice_tokens(slice, &self.consts)
    }

    /// Asserts that the `pub const <slice>` declaration is EXACTLY `allowlist`.
    pub(super) fn assert_exact(&self, slice: &str, allowlist: &[&str], message: &str) {
        assert_eq!(self.declared(slice), token_set(allowlist), "{message}");
    }

    /// Asserts that `category` is exactly its allowlist and that no other slice lists any of
    /// it: each allowlist is its own category.
    pub(super) fn assert_own_category(&self, category: &OwnCategory) {
        self.assert_exact(category.slice, category.allowlist, category.exactly);
        let own = token_set(category.allowlist);
        for other in category.others {
            assert!(
                self.declared(other).is_disjoint(&own),
                "{other} lists {}; it is its own category ({})",
                category.subject,
                category.adr
            );
        }
    }
}

/// An audit category that joins no other slice, with the wording its failures report.
pub(super) struct OwnCategory {
    slice: &'static str,
    allowlist: &'static [&'static str],
    others: &'static [&'static str],
    subject: &'static str,
    adr: &'static str,
    exactly: &'static str,
}

/// The execution intent: a category of its own, so it joins neither the success set nor
/// any other.
pub(super) const EXECUTION: OwnCategory = OwnCategory {
    slice: "EXECUTION_EVENT_TYPES",
    allowlist: EXPECTED_EXECUTION_EVENTS,
    others: &[
        "SUCCESS_EVENT_TYPES",
        "REJECTION_EVENT_TYPES",
        "KEY_LIFECYCLE_EVENT_TYPES",
    ],
    subject: "the execution intent",
    adr: "ADR-MCPRE-070 D1",
    exactly: "audit.rs EXECUTION_EVENT_TYPES must be EXACTLY the one-item allowlist \
         (mcp-re.execution.intent) — no second execution event without an ADR (ADR-MCPRE-070 D1)",
};

/// The accounting record: a category of its own, so the two success events keep their
/// meanings and it joins no other slice.
pub(super) const ACCOUNTING: OwnCategory = OwnCategory {
    slice: "ACCOUNTING_EVENT_TYPES",
    allowlist: EXPECTED_ACCOUNTING_EVENTS,
    others: &[
        "SUCCESS_EVENT_TYPES",
        "REJECTION_EVENT_TYPES",
        "KEY_LIFECYCLE_EVENT_TYPES",
        "EXECUTION_EVENT_TYPES",
    ],
    subject: "the accounting record",
    adr: "ADR-MCPRE-070 Q3",
    exactly: "audit.rs ACCOUNTING_EVENT_TYPES must be EXACTLY the one-item allowlist \
         (mcp-re.audit.accounting) — no second accounting event without an ADR (ADR-MCPRE-070 Q3)",
};
