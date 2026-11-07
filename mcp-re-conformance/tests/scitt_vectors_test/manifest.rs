// SPDX-License-Identifier: Apache-2.0
//! The frozen corpus on disk: fixtures, the manifest that pins them, and the digests.

use mcp_re_core::b64url_encode;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::SignedStatement;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::material::issuer;
use super::material::ts;
use super::material::vectors_root;

/// One frozen vector: the exact wire octets, and the verdict a conforming verifier
/// must reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Fixture {
    pub(super) name: String,
    /// What the vector is for, in one line — a corpus a reader cannot interpret is a
    /// corpus that gets regenerated instead of understood.
    pub(super) description: String,
    /// The tagged `COSE_Sign1` Signed Statement, base64url.
    pub(super) statement_cose_b64url: String,
    /// The tagged `COSE_Sign1` Receipt, base64url.
    pub(super) receipt_cose_b64url: String,
    /// The issuer public key a verifier resolves `issuer_kid` to, base64url.
    pub(super) issuer_pubkey_b64url: String,
    /// The transparency service public key, base64url.
    pub(super) ts_pubkey_b64url: String,
    /// `verify_ok`, or the frozen `mcp-re.*` wire code of the expected refusal.
    pub(super) expect: String,
}

/// What a vector is for and the verdict it expects, before any bytes are attached.
pub(super) struct Case<'a> {
    pub(super) name: &'a str,
    pub(super) description: &'a str,
    pub(super) expect: &'a str,
}

impl Case<'_> {
    /// The fixture carrying `statement` and `receipt` as the corpus keys pin them.
    pub(super) fn pin(&self, statement: &SignedStatement, receipt: &Receipt) -> Fixture {
        Fixture {
            name: self.name.to_owned(),
            description: self.description.to_owned(),
            statement_cose_b64url: b64url_encode(statement.to_cose()),
            receipt_cose_b64url: b64url_encode(receipt.to_cose()),
            issuer_pubkey_b64url: b64url_encode(&issuer().public_key().to_bytes()),
            ts_pubkey_b64url: b64url_encode(&ts().public_key().to_bytes()),
            expect: self.expect.to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ManifestEntry {
    pub(super) file: String,
    pub(super) sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Manifest {
    pub(super) schema: String,
    pub(super) corpus_digest: String,
    pub(super) fixtures: Vec<ManifestEntry>,
}

pub(super) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The corpus digest: SHA-256 over the sorted `file sha256` lines, so the pin is
/// independent of the order the writer happened to emit them in.
pub(super) fn corpus_digest(entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{} {}", e.file, e.sha256))
        .collect();
    lines.sort();
    hex_sha256(lines.join("\n").as_bytes())
}

/// The committed manifest.
pub(super) fn load_manifest() -> Manifest {
    serde_json::from_slice(
        &std::fs::read(vectors_root().join("manifest.json"))
            .expect("the scitt corpus is committed"),
    )
    .expect("manifest parses")
}

/// Every committed vector, read from the bytes on disk and checked against its pin.
pub(super) fn committed_fixtures() -> Vec<Fixture> {
    let root = vectors_root();
    load_manifest()
        .fixtures
        .iter()
        .map(|e| {
            let bytes = std::fs::read(root.join(&e.file)).expect("fixture is committed");
            assert_eq!(
                hex_sha256(&bytes),
                e.sha256,
                "{}: the committed bytes do not match the manifest pin",
                e.file
            );
            serde_json::from_slice(&bytes).expect("fixture parses")
        })
        .collect()
}
