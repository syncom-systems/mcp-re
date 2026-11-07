// SPDX-License-Identifier: Apache-2.0
//! HTTP standards-profile conformance corpus (ADR-MCPRE-050, seed Work Item 4).
//!
//! A SEPARATE corpus under `tests/vectors/http-profile/` — the draft-01 and
//! draft-02 corpora stay byte-frozen and untouched (v0.11 grill I.1). Each
//! fixture freezes the COMPLETE signed HTTP message(s) plus, for verifying
//! fixtures, a static oracle: the exact signature-base bytes, the
//! `Content-Digest` value, the Ed25519 signature (deterministic — byte-compare
//! is honest for Ed25519 ONLY), and the split-form `request_evidence` value.
//!
//! Two-sided guard, mirroring the draft-02 corpus:
//!   1. the writer (`write_http_profile_fixtures -- --ignored`) regenerates the
//!      corpus with the project's own implementation (drift guard);
//!   2. the frozen runner verifies every committed fixture black-box and
//!      byte-compares the oracle fields — a third party checks itself against
//!      the frozen bytes, not this project's regenerated opinion (S8/S15).
//!
//! Regenerate: `bazel build //mcp-re-conformance:http_profile_vectors_test`, then run
//!   `MCP_RE_HTTP_PROFILE_VECTORS_MANIFEST=$PWD/mcp-re-conformance/tests/vectors/http-profile/manifest.json \
//!   bazel-bin/mcp-re-conformance/http_profile_vectors_test write_http_profile_fixtures --ignored --exact`

#[path = "http_profile_vectors_test/admission_vectors.rs"]
mod admission_vectors;
#[path = "http_profile_vectors_test/binding_vectors.rs"]
mod binding_vectors;
#[path = "http_profile_vectors_test/bodyless_vectors.rs"]
mod bodyless_vectors;
#[path = "http_profile_vectors_test/chain_vectors.rs"]
mod chain_vectors;
#[path = "http_profile_vectors_test/delegated_202_vectors.rs"]
mod delegated_202_vectors;
#[path = "http_profile_vectors_test/delegation.rs"]
mod delegation;
#[path = "http_profile_vectors_test/material.rs"]
mod material;
#[path = "http_profile_vectors_test/request_vectors.rs"]
mod request_vectors;
#[path = "http_profile_vectors_test/schema.rs"]
mod schema;
#[path = "http_profile_vectors_test/transport_vectors.rs"]
mod transport_vectors;
#[path = "http_profile_vectors_test/verdicts.rs"]
mod verdicts;

use admission_vectors::admission_fixtures;
use binding_vectors::artifact_fixtures;
use binding_vectors::continuation_fixtures;
use bodyless_vectors::bodyless_202_fixtures;
use chain_vectors::chain_fixtures;
use delegated_202_vectors::delegated_202_fixtures;
use material::NOW;
use request_vectors::rejection_fixtures;
use request_vectors::request_fixtures;
use request_vectors::response_fixtures;
use request_vectors::sse_fixtures;
use schema::corpus_digest;
use schema::hex_sha256;
use schema::vectors_root;
use schema::Fixture;
use schema::Manifest;
use schema::ManifestEntry;
use schema::EXTERNAL_KATS;
use schema::SCHEMA;
use transport_vectors::mcp_header_fixtures;
use transport_vectors::transport_contract_fixtures;

// ---------------------------------------------------------------------------
// Fixture construction (the writer's source of truth).
// ---------------------------------------------------------------------------

/// Every vector, in the order the corpus is written.
fn build_fixtures() -> Vec<Fixture> {
    [
        request_fixtures(),
        response_fixtures(),
        artifact_fixtures(),
        continuation_fixtures(),
        bodyless_202_fixtures(),
        mcp_header_fixtures(),
        transport_contract_fixtures(),
        delegated_202_fixtures(),
        admission_fixtures(),
        sse_fixtures(),
        chain_fixtures(),
        rejection_fixtures(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

// ---------------------------------------------------------------------------
// Writer (regenerates the corpus) — run explicitly with --ignored.
// ---------------------------------------------------------------------------

/// Pin the external KATs too (#415 rev 2 §12.2 names external KATs explicitly).
/// They are NOT generated here — a KAT is a signature produced by python-cryptography
/// independently of ed25519-dalek — which is exactly why it must be pinned: it is the
/// anchor of the cross-verification claim, and if it drifted, that claim would silently
/// change meaning while still passing. The writer hashes it in place and never rewrites it.
fn external_kat_entries(root: &std::path::Path) -> Vec<ManifestEntry> {
    EXTERNAL_KATS
        .iter()
        .map(|external| {
            let bytes = std::fs::read(root.join(external))
                .unwrap_or_else(|_| panic!("{external}: external KAT must be committed"));
            ManifestEntry {
                file: (*external).to_owned(),
                sha256: hex_sha256(&bytes),
            }
        })
        .collect()
}

#[test]
#[ignore = "golden writer: regenerates the committed http-profile corpus"]
fn write_http_profile_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let mut entries = Vec::new();
    for f in &build_fixtures() {
        let file = format!("{}.json", f.name);
        let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
        std::fs::write(root.join(&file), &bytes).expect("write fixture");
        // Hash the bytes actually written — the artifact a third party will read,
        // not the in-memory struct they cannot see.
        entries.push(ManifestEntry {
            sha256: hex_sha256(bytes.as_bytes()),
            file,
        });
    }
    entries.extend(external_kat_entries(&root));

    let manifest = Manifest {
        schema: SCHEMA.into(),
        verify_at_unix: NOW,
        corpus_digest: corpus_digest(&entries),
        fixtures: entries,
    };
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize") + "\n",
    )
    .expect("write manifest");
}

// ---------------------------------------------------------------------------
// Frozen runner: every committed fixture must verify black-box to its
// expected verdict, and oracles must byte-match.
// ---------------------------------------------------------------------------

/// Replay one manifest entry. Fail closed BEFORE running: a vector whose bytes do not
/// match the manifest is not a vector, it is an unknown file with a familiar name.
/// Running it would report a verdict about something nobody pinned.
fn replay_entry(root: &std::path::Path, entry: &ManifestEntry, verify_at: i64) {
    let name = &entry.file;
    let bytes = std::fs::read(root.join(name)).expect("fixture file");
    assert_eq!(
        hex_sha256(&bytes),
        entry.sha256,
        "{name}: fixture bytes do not match the manifest SHA-256"
    );
    // An external KAT is pinned by hash but replayed by its own harness.
    if EXTERNAL_KATS.contains(&name.as_str()) {
        return;
    }
    let fixture: Fixture = serde_json::from_slice(&bytes).expect("fixture parses");
    assert_eq!(
        verdicts::observed(&fixture, verify_at),
        fixture.expected,
        "{name}: verdict mismatch"
    );
}

#[test]
fn frozen_http_profile_corpus_verifies() {
    let root = vectors_root();
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("committed manifest"),
    )
    .expect("manifest parses");
    assert_eq!(manifest.schema, SCHEMA);
    assert!(!manifest.fixtures.is_empty(), "corpus must not be empty");

    // §12.2 content pin: the corpus digest must commit to the manifest's own
    // entries. A tampered entry (or an entry added/removed) breaks this before any
    // vector runs — the digest is checked first precisely so a corpus cannot be
    // edited into agreeing with itself.
    assert_eq!(
        corpus_digest(&manifest.fixtures),
        manifest.corpus_digest,
        "corpus digest does not commit to the manifest entries"
    );

    for entry in &manifest.fixtures {
        replay_entry(&root, entry, manifest.verify_at_unix);
    }
}

/// Drift guard: regenerating the corpus with the current implementation must
/// reproduce the committed bytes exactly (writer output == frozen files).
#[test]
fn regenerated_fixtures_match_committed_bytes() {
    let root = vectors_root();
    for f in build_fixtures() {
        let committed = std::fs::read_to_string(root.join(format!("{}.json", f.name)))
            .expect("committed fixture");
        let regenerated = serde_json::to_string_pretty(&f).expect("serialize") + "\n";
        assert_eq!(
            regenerated, committed,
            "{}: implementation drifted from the frozen corpus",
            f.name
        );
    }
}
