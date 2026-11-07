// SPDX-License-Identifier: Apache-2.0
//! Method-name drift guard (ADR-MCPS-030/034), the STATIC half of the ADR-MCPS-036
//! #150 method-transparency pair. `mcp-re-core` is the pure verification firewall:
//! it must contain NO concrete MCP method-name literal in non-test source, so a
//! future change cannot silently make the Core verdict method-aware.

use std::path::PathBuf;

/// Concrete MCP method-name literals that MUST NOT appear in non-test Core source.
/// A match means Core is branching on (or otherwise encoding) a specific method —
/// a method-transparency violation.
const BANNED_METHOD_LITERALS: &[&str] = &[
    "tools/call",
    "tools/list",
    "resources/read",
    "resources/list",
    "resources/subscribe",
    "resources/templates/list",
    "prompts/get",
    "prompts/list",
    "completion/complete",
    "sampling/createMessage",
    "logging/setLevel",
    "roots/list",
];

/// The `mcp-re-core/src` directory, located from the workspace root the same way the
/// other traceability guards resolve their fixtures.
fn core_src_dir() -> PathBuf {
    let lib = mcp_re_test_paths::resolve_runfile("MCP_RE_CORE_SRC_LIB");
    lib.parent()
        .expect("core src/lib.rs has a parent dir")
        .to_path_buf()
}

/// The non-test region of a source file, so a method literal used only as a test fixture
/// is not a production drift.
///
/// NOT "everything before the first `#[cfg(test)]`". Unit tests live at file end by
/// convention, and a convention is not the property this guard claims: a production item
/// below a test module, or an inline `#[cfg(test)]` helper above one, both make truncation
/// report a clean pass over code it never read. [`mcp_re_test_paths::rust_source`] owns the
/// region definition, shared with every sibling source-scanning gate.
fn non_test_region(text: &str) -> String {
    mcp_re_test_paths::rust_source::production_half(text)
}

#[test]
fn the_region_scan_looks_below_a_test_module() {
    let source = "#[cfg(test)]\nmod tests {\n    let m = \"tools/call\";\n}\nconst LATE: &str = \"resources/list\";\n";
    let production = non_test_region(source);
    assert!(
        !production.contains("tools/call"),
        "a fixture inside the test module must stay out of scope"
    );
    assert!(
        production.contains("resources/list"),
        "production below the test module must still be scanned"
    );
}

/// The `.rs` files directly under `dir`.
fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect()
}

/// One finding per banned method literal the production half of `path` contains.
fn banned_literals_in(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let region = non_test_region(&text);
    BANNED_METHOD_LITERALS
        .iter()
        .filter(|literal| region.contains(**literal))
        .map(|literal| {
            format!(
                "{:?} contains banned method literal {literal:?}",
                path.file_name().unwrap()
            )
        })
        .collect()
}

#[test]
fn no_banned_method_literal_in_non_test_core_src() {
    let found: Vec<String> = rust_sources(&core_src_dir())
        .iter()
        .flat_map(|path| banned_literals_in(path))
        .collect();
    assert!(
        found.is_empty(),
        "mcp-re-core non-test source contains concrete MCP method-name literal(s) — Core must \
         stay method-transparent (ADR-MCPS-030/034): {found:?}"
    );
}
