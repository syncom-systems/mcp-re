// SPDX-License-Identifier: Apache-2.0
//! Frozen conformance vectors for the SCITT Signed Statement + COSE Receipt
//! encoding (RFC 9052 / RFC 9942 / RFC 9943) — MCPRE-494.
//!
//! **Why these could not exist before.** The prototype serialized statements and
//! receipts as JSON, an explicit stand-in. Pinning those bytes would have certified a
//! non-wire format: a third party implementing RFC 9943 would have matched nothing,
//! and the corpus would have said they were wrong. So #494 held the rule "no vectors
//! before the encoding is real". The encoding is now real, and these are frozen from
//! it.
//!
//! What each vector pins is the exact `COSE_Sign1` octets — tag 18, protected header,
//! payload, signature — so a change to the encoder that alters the wire form fails
//! here rather than silently producing bytes only this implementation accepts.
//!
//! The negatives matter more than the positive. A corpus that only proves a good
//! receipt verifies says nothing about what an implementation must REFUSE, and every
//! interesting SCITT failure is a refusal: a tampered payload, a forged inclusion
//! path, an untrusted issuer, a leaf index the signed tree cannot contain, a
//! verifiable-data-structure this verifier does not implement.
//!
//! Three of those negatives leave the transparency service's signature VALID and are
//! caught by nothing else — the inclusion path and the leaf index ride in the
//! unprotected header, so a verifier that checked the two signatures and skipped the
//! fold would accept them.
//!
//! These tests cannot see whether the labels are the RIGHT ones: they run the encoder
//! against its own decoder, which agrees with itself whatever numbers it picks.
//! `mcp-re-conformance/tools/scitt_cross_verify.py` is the outside opinion, built from
//! the RFC text with no MCP-RE code, and it is what to run when the encoding changes.
//! Its Merkle tree and inclusion fold are transcribed from RFC 9162 §2.1.1/§2.1.3.2
//! rather than shared with the Rust — a second implementation of the same misreading
//! is not independent evidence, which is exactly how a duplicate-last-node tree
//! survived on both sides of this check.
//!
//! Regenerate (and re-pin) with:
//!   bazel run //mcp-re-conformance:scitt_vectors_test -- \
//!     write_scitt_fixtures --ignored

#[path = "scitt_vectors_test/bytes.rs"]
mod bytes;
#[path = "scitt_vectors_test/manifest.rs"]
mod manifest;
#[path = "scitt_vectors_test/material.rs"]
mod material;
#[path = "scitt_vectors_test/vectors.rs"]
mod vectors;
#[path = "scitt_vectors_test/verdict.rs"]
mod verdict;

use manifest::committed_fixtures;
use manifest::corpus_digest;
use manifest::hex_sha256;
use manifest::load_manifest;
use manifest::Manifest;
use manifest::ManifestEntry;
use material::vectors_root;
use mcp_re_core::b64url_decode;
use vectors::build_fixtures;
use verdict::verdict;

// ---------------------------------------------------------------------------
// Writer — run explicitly with --ignored.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "golden writer: regenerates the committed scitt corpus"]
fn write_scitt_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let mut entries = Vec::new();
    for f in &build_fixtures() {
        let file = format!("{}.json", f.name);
        let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
        std::fs::write(root.join(&file), &bytes).expect("write fixture");
        // Hash the bytes actually written — the artifact a third party reads, not the
        // in-memory struct they cannot see.
        entries.push(ManifestEntry {
            sha256: hex_sha256(bytes.as_bytes()),
            file,
        });
    }
    let manifest = Manifest {
        schema: "mcp-re-scitt-conformance/v1".into(),
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
// Frozen runner — every committed vector must reach its expected verdict from the
// bytes on disk, never from a freshly regenerated opinion.
// ---------------------------------------------------------------------------

#[test]
fn every_committed_vector_reaches_its_expected_verdict() {
    let fixtures = committed_fixtures();
    assert!(!fixtures.is_empty(), "the corpus must not be empty");
    for f in &fixtures {
        assert_eq!(verdict(f), f.expect, "{}: {}", f.name, f.description);
    }
}

#[test]
fn the_corpus_digest_pins_the_whole_set() {
    // A per-file hash catches an edited vector; the corpus digest catches a DELETED
    // one, which per-file hashes cannot see.
    let manifest = load_manifest();
    assert_eq!(
        corpus_digest(&manifest.fixtures),
        manifest.corpus_digest,
        "the corpus digest does not cover the committed fixture set"
    );
}

/// Whether `name` is a vector this writer owns, and so must be pinned in the manifest.
///
/// `external_kat.json` is the external → us corpus, built by
/// `tools/scitt_cross_verify.py` rather than by this writer, and pinned by the
/// CI drift guard that regenerates it and diffs. It is deliberately not in this
/// manifest: a corpus MCP-RE produced and a corpus MCP-RE must merely accept are
/// different artifacts, and freezing the second here would let our own encoder
/// define what "external" means.
fn is_writer_vector(name: &str) -> bool {
    let not_a_vector = name == "manifest.json" || name == "external_kat.json";
    name.ends_with(".json") && !not_a_vector
}

#[test]
fn the_corpus_directory_holds_no_unpinned_vector() {
    // The digest catches a deleted fixture; neither it nor the per-file hashes can see
    // an EXTRA one. An unlisted vector is read by no test, so its expectation drifts
    // out of date invisibly — and a reader who finds it in the corpus has no way to
    // tell it is stale. The corpus is exactly what the manifest lists.
    let root = vectors_root();
    let manifest = load_manifest();
    let pinned: Vec<&str> = manifest.fixtures.iter().map(|e| e.file.as_str()).collect();
    for entry in std::fs::read_dir(&root).expect("corpus dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        if !is_writer_vector(&name) {
            continue;
        }
        assert!(
            pinned.contains(&name.as_ref()),
            "{name} is in the corpus but not in the manifest"
        );
    }
}

#[test]
fn regenerated_fixtures_match_the_committed_bytes() {
    // Determinism: the encoding is signed over fixed inputs with fixed keys, so
    // regenerating must reproduce the frozen octets. If it does not, either the
    // encoder changed (and the corpus must be re-pinned deliberately) or something
    // non-deterministic crept into the wire form — and a non-deterministic wire form
    // cannot be pinned by anyone.
    let committed = committed_fixtures();
    let regenerated = build_fixtures();
    assert_eq!(committed.len(), regenerated.len());
    for (c, r) in committed.iter().zip(regenerated.iter()) {
        assert_eq!(c.name, r.name);
        assert_eq!(
            c.statement_cose_b64url, r.statement_cose_b64url,
            "{}: statement wire bytes drifted",
            c.name
        );
        assert_eq!(
            c.receipt_cose_b64url, r.receipt_cose_b64url,
            "{}: receipt wire bytes drifted",
            c.name
        );
    }
}

/// The wire form must be a TAGGED COSE_Sign1 (tag 18, RFC 9052 §2). An untagged
/// structure is a different thing on the wire, and a consumer that guessed would be
/// interoperating by accident.
#[test]
fn the_wire_form_is_a_tagged_cose_sign1() {
    for f in committed_fixtures() {
        for (what, b64) in [
            ("statement", &f.statement_cose_b64url),
            ("receipt", &f.receipt_cose_b64url),
        ] {
            let bytes = b64url_decode(b64).expect("b64url");
            assert_eq!(
                bytes[0], 0xd2,
                "{}: {what} must start with CBOR tag 18 (0xd2)",
                f.name
            );
        }
    }
}
