#![cfg(test)]
//! Reading the guard's inputs from DISK through Bazel runfiles (the same scheme as the
//! conformance drift_guard), and the table that says which runfile delivers which source.

/// The text of the runfile the environment variable `env_key` names.
pub(super) fn read(env_key: &str) -> String {
    let path = mcp_re_test_paths::resolve_runfile(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// Manifest `source` workspace-relative path → the env var that delivers its
/// runfile. Sources are handed individually so the guard can read each one.
///
/// `the_source_table_names_exactly_the_manifest_sources` pins this to the
/// manifest in both directions, because only one of them is self-announcing:
/// a source with no entry here panics on first use, while an entry for a
/// source the manifest does not name is simply never consulted again.
pub(super) const SOURCE_ENVS: &[(&str, &str)] = &[
    (
        "mcp-re-conformance/tests/method_transparency_test.rs",
        "MCP_RE_SRC_METHOD_TRANSPARENCY",
    ),
    (
        "mcp-re-conformance/tests/method_name_drift_guard_test.rs",
        "MCP_RE_SRC_METHOD_NAME_DRIFT_GUARD",
    ),
    (
        "mcp-re-conformance/tests/audit_vocabulary_guard_test.rs",
        "MCP_RE_SRC_AUDIT_VOCABULARY_GUARD",
    ),
    (
        "mcp-re-conformance/tests/forbidden_claim_guard_test.rs",
        "MCP_RE_SRC_FORBIDDEN_CLAIM_GUARD",
    ),
    (
        "mcp-re-conformance/tests/rfc9421_security_properties_test.rs",
        "MCP_RE_SRC_RFC9421_SECURITY_PROPERTIES",
    ),
    // MCPRE-122 (ADR-MCPRE-052): the delegated-required validation matrix — the
    // serving contract, the production wiring (serve/verify/rotate/fail-closed),
    // the two-proxy client↔server round trip, and the frozen credential-
    // verification corpus. See docs/spec/delegated-required-validation-matrix.md.
    (
        "mcp-re-proxy/tests/integration_async/delegated_serving_test.rs",
        "MCP_RE_SRC_DELEGATED_SERVING",
    ),
    (
        "mcp-re-proxy/tests/integration_async/delegated_production_wiring_test.rs",
        "MCP_RE_SRC_DELEGATED_PROD_WIRING",
    ),
    (
        "mcp-re-proxy/tests/integration_async/delegated_client_server_e2e_test.rs",
        "MCP_RE_SRC_DELEGATED_E2E",
    ),
    (
        "mcp-re-conformance/tests/delegation_vectors_test.rs",
        "MCP_RE_SRC_DELEGATION_VECTORS",
    ),
    // ADR-MCPRE-052 trust-anchor (master/root key) lifecycle — rotation overlap,
    // cutover, issuer revocation, and root issuance failure (§H of the matrix).
    (
        "mcp-re-proxy/tests/integration_async/root_key_lifecycle_test.rs",
        "MCP_RE_SRC_ROOT_KEY_LIFECYCLE",
    ),
    // ADR-MCPRE-052 §I: signed trust-anchor-manifest root rotation with an
    // auto-provisioned root (the hermetic twin of the live KMS lane).
    (
        "mcp-re-proxy/tests/integration_async/root_authority_manifest_test.rs",
        "MCP_RE_SRC_ROOT_AUTHORITY_MANIFEST",
    ),
    // ADR-MCPS-047: stateless cross-replica MRT continuation — open-on-A/answer-on-B
    // + fail-closed splice/one-shot binding.
    (
        "mcp-re-proxy/tests/integration_async/mrt_continuation_serving_test/binding_cases.rs",
        "MCP_RE_SRC_MRT_CONTINUATION",
    ),
    // MCPS-72 (#252): the KMS-lifecycle offline negatives are in-crate
    // `#[cfg(test)]` unit tests, so their `source` is a `src/*.rs` file (not a
    // `tests/*.rs`). The generic provider-agnostic signer seam runs under the
    // default-feature `proxy_unit_test`; the GCP/AWS backend negatives run under
    // the both-KMS-features `proxy_ext_unit_test`. All three sources are read
    // from DISK the same way (runfile via the guard BUILD `data`).
    (
        "mcp-re-proxy/src/kms_keysource/mod.rs",
        "MCP_RE_SRC_KMS_KEYSOURCE",
    ),
    (
        "mcp-re-proxy/src/gcp_kms_keysource.rs",
        "MCP_RE_SRC_GCP_KMS_KEYSOURCE",
    ),
    (
        "mcp-re-proxy/src/aws_kms_keysource.rs",
        "MCP_RE_SRC_AWS_KMS_KEYSOURCE",
    ),
    (
        "mcp-re-transport/tests/mtls_client_test.rs",
        "MCP_RE_SRC_MTLS_CLIENT",
    ),
    (
        "mcp-re-proxy/tests/key_source_test.rs",
        "MCP_RE_SRC_KEY_SOURCE",
    ),
    // MCPS-62 (ADR-MCPS-023 §C, v0.10 Mode C): the Mode-C CLI guards + the
    // Mode-B lb-assertion strict-rejection conformance are in-crate `#[cfg(test)]`
    // unit tests in `cli.rs` (run under `proxy_unit_test`).
    ("mcp-re-proxy/src/cli.rs", "MCP_RE_SRC_CLI"),
];

fn source_env_for(source: &str) -> &'static str {
    let Some((_, env)) = SOURCE_ENVS.iter().find(|(path, _)| *path == source) else {
        panic!(
            "manifest 'source' {source:?} has no runfile wired in the guard BUILD target. \
             Add a data entry + env var for it (so the guard can read the test fn)."
        );
    };
    env
}

/// The text of the manifest `source` file, read from its runfile.
pub(super) fn read_source(source: &str) -> String {
    read(source_env_for(source))
}

/// `true` iff the text declares a free function `fn <name>(` (the form every
/// `#[test]` uses). Tolerates `pub`/`async` and arbitrary leading whitespace by
/// matching the `fn <name>(` token directly.
pub(super) fn declares_fn(text: &str, name: &str) -> bool {
    let needle = format!("fn {name}(");
    text.contains(&needle)
}
