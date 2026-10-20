// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-070 G1: the backend is transmitted to only through the ready state.
//!
//! `PreparedInnerDispatch::dispatch` is `pub`, because the inner-plane seam is implemented
//! in its own module tree. So "only `ReadyForDispatch` transmits" — and with it "no dispatch
//! without the intent disposition the ready state requires" — is held by the call graph, not
//! by the type: any production code holding a prepared capability could call it directly and
//! skip G1. This control measures the call graph. Over the production half of every source
//! file of the crate outside the seam's own tree (`async_inner/`), the only `.dispatch()`
//! calls are the ready state's own transmission and the assembly's one crossing.

use std::path::{Path, PathBuf};

/// The receiver-qualified calls that may transmit, and where.
const ALLOWED: &[(&str, &str)] = &[
    ("request_stages.rs", "prepared.dispatch()"),
    ("http_profile_serve/mod.rs", "ready.dispatch()"),
];

fn collect(dir: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// Every `<receiver>.dispatch()` call in `source`'s production half, with its receiver.
fn dispatch_calls(source: &str) -> Vec<String> {
    let production = mcp_re_test_paths::rust_source::production_half(source);
    let mut calls = Vec::new();
    for line in production.lines() {
        let code = line.split("//").next().unwrap_or_default();
        let mut rest = code;
        while let Some(at) = rest.find(".dispatch()") {
            let receiver: String = rest[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            calls.push(format!("{receiver}.dispatch()"));
            rest = &rest[at + ".dispatch()".len()..];
        }
    }
    calls
}

/// The crate's `src/` and every production-half `.dispatch()` call outside the seam, as
/// `(path relative to src, call)`.
fn crate_calls() -> (usize, Vec<(String, String)>) {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_HTTP_PROFILE_SERVE_SRC");
    let src = anchor
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("{anchor:?} is not under src/http_profile_serve"))
        .to_path_buf();
    let mut files = Vec::new();
    collect(&src, &mut files);
    files.sort();
    let mut found = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("async_inner/") {
            continue;
        }
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        found.extend(dispatch_calls(&text).into_iter().map(|c| (rel.clone(), c)));
    }
    (files.len(), found)
}

#[test]
fn prepared_dispatch_is_transmitted_only_by_the_ready_state() {
    let (scanned, found) = crate_calls();
    assert!(
        scanned >= 200,
        "the walk read {scanned} files — the runfiles wiring is broken and this measures nothing"
    );
    let expected: Vec<(String, String)> = ALLOWED
        .iter()
        .map(|(file, call)| (file.to_string(), call.to_string()))
        .collect();
    let mut found = found;
    found.sort();
    let mut expected_sorted = expected.clone();
    expected_sorted.sort();
    assert_eq!(
        found, expected_sorted,
        "a production `.dispatch()` call outside the ready state transmits without the \
         prerequisites `ReadyForDispatch::new` requires — the intent disposition among them \
         (ADR-MCPRE-070 G1). Route it through the ready state."
    );
}

/// Sensitivity: the scanner sees a direct call, its receiver, and ignores comments and the
/// test half — so the equality above can fail.
#[test]
fn the_scanner_sees_a_bypass_and_ignores_comments_and_tests() {
    let bypass = "fn skip(p: P) {\n    let _ = p.dispatch();\n    // ready.dispatch()\n}\n\
                  #[cfg(test)]\nmod tests {\n    fn t() { prepared.dispatch(); }\n}\n";
    assert_eq!(dispatch_calls(bypass), ["p.dispatch()"]);
}
