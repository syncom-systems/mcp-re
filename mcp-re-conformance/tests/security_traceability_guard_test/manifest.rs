#![cfg(test)]
//! The security traceability manifest, read as entries rather than as JSON.

use serde_json::Value;

use super::runfiles::read;

/// The committed manifest: the map from each security property to the Bazel test target and
/// test function that prove it.
pub(super) struct Manifest(Value);

impl Manifest {
    pub(super) fn load() -> Self {
        Self(
            serde_json::from_str(&read("MCP_RE_SECURITY_MANIFEST"))
                .expect("security_traceability_manifest.json parses"),
        )
    }

    fn entry_array(&self) -> &Vec<Value> {
        self.0["entries"].as_array().expect("entries is an array")
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = Entry<'_>> {
        self.entry_array().iter().map(Entry)
    }

    pub(super) fn len(&self) -> usize {
        self.entry_array().len()
    }

    /// The `counts.entries` the manifest records about itself.
    pub(super) fn recorded_count(&self) -> u64 {
        self.0["counts"]["entries"]
            .as_u64()
            .expect("counts.entries is a u64")
    }

    /// Every `property` string the manifest declares.
    pub(super) fn properties(&self) -> Vec<String> {
        self.entries().map(|e| e.property().to_string()).collect()
    }

    /// Whether some entry names `test_fn` under `target`.
    pub(super) fn maps(&self, target: &str, test_fn: &str) -> bool {
        self.entries()
            .any(|e| e.target() == target && e.test_fn() == test_fn)
    }
}

/// One manifest entry.
#[derive(Clone, Copy)]
pub(super) struct Entry<'a>(&'a Value);

impl<'a> Entry<'a> {
    fn field(self, key: &str) -> &'a str {
        self.0[key]
            .as_str()
            .unwrap_or_else(|| panic!("entry missing string field '{key}': {}", self.0))
    }

    pub(super) fn target(self) -> &'a str {
        self.field("bazel_target")
    }

    pub(super) fn source(self) -> &'a str {
        self.field("source")
    }

    pub(super) fn test_fn(self) -> &'a str {
        self.field("test_fn")
    }

    pub(super) fn property(self) -> &'a str {
        self.field("property")
    }

    /// Whether the source path belongs to the target's package: `//mcp-re-demo:x` ⇒ the
    /// source starts with `mcp-re-demo/`.
    pub(super) fn source_is_in_target_package(self) -> bool {
        let package = self
            .target()
            .split(':')
            .next()
            .and_then(|p| p.strip_prefix("//"))
            .unwrap_or("");
        self.source().starts_with(&format!("{package}/"))
    }
}
