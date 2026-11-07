#![cfg(test)]
//! The `nt_rust_test` targets the handed BUILD files declare.

use std::collections::BTreeSet;

use super::runfiles::read;

/// The map from `//<package>` label-prefix to the env var carrying that
/// package's BUILD.bazel runfile path. These are the packages every manifest
/// `bazel_target` is allowed to reference.
const BUILD_ENVS: &[(&str, &str)] = &[
    ("//mcp-re-conformance", "MCP_RE_BUILD_CONFORMANCE"),
    ("//mcp-re-core", "MCP_RE_BUILD_CORE"),
    ("//mcp-re-host", "MCP_RE_BUILD_HOST"),
    ("//mcp-re-policy", "MCP_RE_BUILD_POLICY"),
    ("//mcp-re-proxy", "MCP_RE_BUILD_PROXY"),
    ("//mcp-re-demo", "MCP_RE_BUILD_DEMO"),
    ("//mcp-re-transport", "MCP_RE_BUILD_TRANSPORT"),
];

/// Every `//<pkg>:<name>` test target declared by an `nt_rust_test(` rule in any
/// of the handed BUILD files. A hand-rolled scan (no Starlark parser): find each
/// `nt_rust_test(` and take the first `name = "..."` that follows it.
pub(super) fn declared_test_targets() -> BTreeSet<String> {
    BUILD_ENVS
        .iter()
        .flat_map(|(package, env_key)| {
            test_names_in_build(&read(env_key))
                .into_iter()
                .map(move |name| format!("{package}:{name}"))
        })
        .collect()
}

/// The first double-quoted string after the first `name` at or past `from`.
fn quoted_name_after(text: &str, from: usize) -> Option<&str> {
    let after_name = from + text[from..].find("name")?;
    let open = after_name + text[after_name..].find('"')? + 1;
    let close = open + text[open..].find('"')?;
    Some(&text[open..close])
}

fn test_names_in_build(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("nt_rust_test(") {
        let block_start = search_from + rel + "nt_rust_test(".len();
        names.extend(quoted_name_after(text, block_start).map(str::to_string));
        search_from = block_start;
    }
    names
}
