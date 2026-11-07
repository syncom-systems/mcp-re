//! Reading the two vocabularies off disk: runfile resolution and the `mcp-re.*` string-literal
//! parsers every drift condition rests on.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The runfile an env key names.
pub(super) fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

/// A Rust source file's text, read through the parsers the drift conditions rest on.
pub(super) struct Source {
    text: String,
}

impl Source {
    pub(super) fn new(text: String) -> Self {
        Self { text }
    }

    /// The source the runfile an env key names holds.
    pub(super) fn runfile(env_key: &str) -> Self {
        let path = locate(env_key);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        Self::new(text)
    }

    /// Whether the text holds `needle`.
    pub(super) fn contains(&self, needle: &str) -> bool {
        self.text.contains(needle)
    }

    /// The text outside every `#[cfg(test)]` item, not everything above the first one: a
    /// token minted below the test module is still minted.
    fn production_half(&self) -> String {
        mcp_re_test_paths::rust_source::production_half(&self.text)
    }

    /// Every `mcp-re.*` wire token the frozen taxonomy renders, parsed from the
    /// `wire_code()` match arms in `error.rs`. We scan the `=> "mcp-re...."` string
    /// literals so a newly added `McpReError` variant (with its new wire_code) is
    /// picked up automatically — exactly the frozen-taxonomy process ADR-MCPS-035
    /// relies on. We start the scan at the `fn wire_code` token so the guard reads
    /// the authority it claims to read.
    pub(super) fn frozen_wire_codes(&self) -> BTreeSet<String> {
        let body = self
            .text
            .split_once("fn wire_code")
            .map(|(_, after)| after)
            .unwrap_or_else(|| panic!("error.rs has no `fn wire_code` — frozen taxonomy moved?"));
        Source::new(body.to_string()).mcp_re_literals()
    }

    /// Every `mcp-re.*` token in the production half: the event_type constants, the
    /// allowlists, the doc examples. Scanning only that region keeps the unit-test fixtures
    /// (which deliberately mention bogus tokens like the bare "authorization_hash_mismatch"
    /// they assert must NOT appear) out of the vocabulary set.
    pub(super) fn production_literals(&self) -> BTreeSet<String> {
        Source::new(self.production_half()).mcp_re_literals()
    }

    /// The VERDICT tokens in the production half: `mcp-re.<name>` with no further dot.
    ///
    /// The dotted spellings are audit event types, a separate vocabulary with its own exact
    /// allowlists. Conflating the two would report `audit.rs` as a third minting authority,
    /// which it is not — it names events, never verdicts.
    pub(super) fn production_verdict_tokens(&self) -> BTreeSet<String> {
        self.production_literals()
            .into_iter()
            .filter(|token| !token.trim_start_matches("mcp-re.").contains('.'))
            .collect()
    }

    /// The body of a `pub const <NAME>: &[&str] = &[ ... ];` slice declared in
    /// `audit.rs`, i.e. everything between the value opener `= &[` and its closing
    /// `]`. Anchoring on `= &[` skips the `&[&str]` TYPE annotation's brackets.
    fn slice_value_body(&self, const_name: &str) -> String {
        let after_name = self
            .text
            .split_once(&format!("pub const {const_name}"))
            .map(|(_, a)| a)
            .unwrap_or_else(|| panic!("audit.rs declares `pub const {const_name}`"));
        // Collapse whitespace so a value split across lines (`=\n    &[...`) still
        // matches the `= &[` anchor; the `&[&str]` TYPE annotation precedes the `=`.
        let collapsed: String = after_name.split_whitespace().collect::<Vec<_>>().join(" ");
        let after_eq = collapsed
            .split_once("= &[")
            .map(|(_, a)| a.to_string())
            .unwrap_or_else(|| panic!("`{const_name}` is not in the `= &[ ... ]` form"));
        after_eq
            .split_once(']')
            .map(|(b, _)| b.to_string())
            .unwrap_or_else(|| panic!("`{const_name}` slice has no closing `]`"))
    }

    /// The `event_type` module's `pub const NAME: &str = "mcp-re...."` map, parsed from
    /// `audit.rs`. Lets the guard resolve a const reference (e.g. the
    /// `SUCCESS_EVENT_TYPES` slice lists `event_type::REQUEST_ACCEPTED`) back to its
    /// `mcp-re.*` string value without depending on literal duplication.
    pub(super) fn event_type_consts(&self) -> Vec<(String, String)> {
        self.text
            .lines()
            .filter_map(|line| Source::new(line.to_string()).event_type_const())
            .collect()
    }

    /// One `pub const REQUEST_ACCEPTED: &str = "mcp-re.request.accepted";` line, as the
    /// `(name, value)` pair, or `None` for any other text.
    fn event_type_const(&self) -> Option<(String, String)> {
        let rest = self.text.trim().strip_prefix("pub const ")?;
        let (name, after) = rest.split_once(':')?;
        let mut quoted = after.split('"').skip(1);
        let value = quoted.next()?;
        quoted.next()?;
        value
            .starts_with("mcp-re.")
            .then(|| (name.trim().to_string(), value.to_string()))
    }

    /// The `mcp-re.*` values the `pub const <slice>` declaration lists, where each element
    /// is either a bare string literal OR an `event_type::NAME` reference resolved through
    /// `consts`.
    pub(super) fn slice_tokens(
        &self,
        slice: &str,
        consts: &[(String, String)],
    ) -> BTreeSet<String> {
        let body = self.slice_value_body(slice);
        let mut out = Source::new(body.clone()).mcp_re_literals();
        for (name, value) in consts {
            if body.contains(&format!("event_type::{name}")) {
                out.insert(value.clone());
            }
        }
        out
    }
}

impl Source {
    /// Every double-quoted string literal beginning with `mcp-re.`.
    ///
    /// Literals are the segments between a quote and the next one; no escaped quotes occur in
    /// these tokens, and a quote with no closing partner opens nothing.
    fn mcp_re_literals(&self) -> BTreeSet<String> {
        let segments: Vec<&str> = self.text.split('"').collect();
        let closed = segments.len().saturating_sub(1);
        segments
            .into_iter()
            .take(closed)
            .skip(1)
            .step_by(2)
            .filter(|literal| literal.starts_with("mcp-re."))
            .map(str::to_string)
            .collect()
    }
}
