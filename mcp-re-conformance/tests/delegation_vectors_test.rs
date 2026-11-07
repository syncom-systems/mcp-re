// SPDX-License-Identifier: Apache-2.0
//! Delegated-signing conformance corpus (ADR-MCPRE-052 §9, MCPRE-122).
//!
//! A SEPARATE frozen corpus under `tests/vectors/delegation-profile/`, sibling to
//! the HTTP-profile corpus (`http_profile_vectors_test.rs`) — the compact-JWS
//! delegation credential + delegated-key RFC 9421 response, verified black-box
//! through the ONE production entry point `verify_delegated_response_full`
//! (ADR-MCPRE-052 §3 steps 1–8). Every §9 vector is a self-contained, frozen
//! request + delegated response + verifier-policy `check`; the runner recomputes
//! the verified request, verifies the delegated response, and asserts the exact
//! frozen `mcp-re.*` verdict.
//!
//! Two-sided guard, mirroring the draft-02 / http-profile corpora:
//!   1. the writer (`write_delegation_fixtures -- --ignored`) regenerates the
//!      corpus with the project's own implementation (drift guard);
//!   2. the frozen runner verifies every committed fixture black-box and asserts
//!      the frozen verdict — a third party checks itself against the frozen bytes,
//!      not this project's regenerated opinion.
//!
//! Cross-verification against an INDEPENDENT JOSE/JWS implementation
//! (`external_delegation_kat.json`, produced by python-cryptography Ed25519) runs
//! in `delegation_cross_verification_test.rs` + `tools/jose_cross_verify.py`
//! (ADR-MCPRE-052 §9; mirrors the RFC 9421 gate, MCPRE-99).
//!
//! Regenerate (writes through the runfiles symlinks into the source tree):
//!   bazel run //mcp-re-conformance:delegation_vectors_test -- \
//!     write_delegation_fixtures --ignored --exact

#[path = "delegation_vectors_test/claim_vectors.rs"]
mod claim_vectors;
#[path = "delegation_vectors_test/credential.rs"]
mod credential;
#[path = "delegation_vectors_test/key_vectors.rs"]
mod key_vectors;
#[path = "delegation_vectors_test/material.rs"]
mod material;
#[path = "delegation_vectors_test/policy_vectors.rs"]
mod policy_vectors;
#[path = "delegation_vectors_test/schema.rs"]
mod schema;
#[path = "delegation_vectors_test/vectors.rs"]
mod vectors;
#[path = "delegation_vectors_test/verdict.rs"]
mod verdict;

use std::collections::BTreeSet;
use std::path::Path;

use material::NOW;
use schema::corpus_digest;
use schema::hex_sha256;
use schema::vectors_root;
use schema::Fixture;
use schema::Manifest;
use schema::ManifestEntry;
use schema::EXTERNAL_KATS;
use schema::SCHEMA;
use vectors::build_fixtures;
use verdict::run_fixture;

// ---------------------------------------------------------------------------
// Writer (regenerates the corpus) — run explicitly with --ignored.
// ---------------------------------------------------------------------------

/// Write every generated fixture under `root`, returning the manifest entries.
fn write_fixtures(root: &Path) -> Vec<ManifestEntry> {
    build_fixtures()
        .iter()
        .map(|f| {
            let file = format!("{}.json", f.name);
            let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
            std::fs::write(root.join(&file), &bytes).expect("write fixture");
            // Hash the bytes actually written — the artifact a third party reads.
            ManifestEntry {
                sha256: hex_sha256(bytes.as_bytes()),
                file,
            }
        })
        .collect()
}

/// Pin the external KATs (#415 rev 2 §12.2 names them explicitly). They are
/// third-party artifacts, not generated here — which is precisely why they need
/// pinning: they anchor the independent cross-verification claim, and silent drift
/// would change what that claim means while still passing.
fn pin_external_kats(root: &Path) -> Vec<ManifestEntry> {
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
#[ignore = "golden writer: regenerates the committed delegation corpus"]
fn write_delegation_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let mut entries = write_fixtures(&root);
    entries.extend(pin_external_kats(&root));

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
// Frozen runner: every committed fixture verifies black-box to its verdict.
// ---------------------------------------------------------------------------

/// Check one manifest entry's bytes, then replay it (an external KAT is pinned by
/// hash but replayed by its own harness).
fn replay_entry(root: &Path, entry: &ManifestEntry, verify_at: i64) {
    let name = &entry.file;
    let bytes = std::fs::read(root.join(name)).expect("fixture file");
    // Fail closed BEFORE running: a fixture whose bytes do not match the
    // manifest is an unknown file with a familiar name.
    assert_eq!(
        hex_sha256(&bytes),
        entry.sha256,
        "{name}: fixture bytes do not match the manifest SHA-256"
    );
    if EXTERNAL_KATS.contains(&name.as_str()) {
        return;
    }
    let fixture: Fixture = serde_json::from_slice(&bytes).expect("fixture parses");
    assert_eq!(
        fixture.kind, "delegated_response",
        "{name}: unexpected kind"
    );
    let observed = run_fixture(&fixture, verify_at);
    assert_eq!(observed, fixture.expected, "{name}: verdict mismatch");
}

#[test]
fn frozen_delegation_corpus_verifies() {
    let root = vectors_root();
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("committed manifest"),
    )
    .expect("manifest parses");
    assert_eq!(manifest.schema, SCHEMA);
    assert!(!manifest.fixtures.is_empty(), "corpus must not be empty");

    // §12.2: the digest must commit to the manifest's entries, checked before any
    // vector runs so a corpus cannot be edited into agreeing with itself.
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
fn regenerated_delegation_fixtures_match_committed_bytes() {
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

/// Every frozen delegation wire token the corpus must exercise as a verdict.
const FROZEN_TOKENS: [&str; 10] = [
    "mcp-re.delegation_credential_missing",
    "mcp-re.delegation_credential_invalid",
    "mcp-re.delegation_credential_expired",
    "mcp-re.delegation_issuer_untrusted",
    "mcp-re.delegation_profile_mismatch",
    "mcp-re.delegation_audience_mismatch",
    "mcp-re.delegation_key_use_invalid",
    "mcp-re.delegation_trust_epoch_stale",
    "mcp-re.delegation_key_mismatch",
    "mcp-re.delegation_revoked",
];

/// Sanity: the §9 plan enumerates 12 numbered vectors (several with sub-cases);
/// the corpus must be comprehensive, not a token stub.
#[test]
fn corpus_covers_the_full_taxonomy() {
    let fixtures = build_fixtures();
    let names: BTreeSet<&str> = fixtures.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names.len() >= 22,
        "corpus shrank below the §9 taxonomy: {}",
        names.len()
    );
    // The corpus exercises the whole taxonomy, not a subset.
    let verdicts: BTreeSet<&str> = fixtures.iter().map(|f| f.expected.as_str()).collect();
    for token in FROZEN_TOKENS {
        assert!(verdicts.contains(token), "corpus never exercises {token}");
    }
}
