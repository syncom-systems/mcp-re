// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! `verification-report.json` — emitted by the verifier, re-checked by a test.

use std::path::PathBuf;

use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;

use super::corpus::{
    another_ed25519_key, artifact, capsule, capsule_dir, interop_dir, operated_capsule,
    operated_capsule_dir, pin_document_with, verify_with,
};

/// One corpus's report: what was verified, by what, and the verdict reached.
///
/// Written by the verifier itself rather than by hand, because a hand-written report is
/// a claim about a run and this has to be a record OF one. The check below re-derives
/// every field, so a report that drifts from what the verifier now does fails.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct VerificationReport {
    pub(super) schema: String,
    pub(super) peer: String,
    pub(super) verifier: String,
    /// The test that emits and re-checks this file.
    pub(super) generated_by: String,
    /// Artifact name → base64url SHA-256, over the bytes on disk.
    pub(super) artifacts: std::collections::BTreeMap<String, String>,
    /// The verdict on the positive case: `verify_ok`, or the refusing wire code.
    pub(super) positive_verdict: String,
    /// Each mutation and the wire code it was refused with.
    pub(super) refusals: std::collections::BTreeMap<String, String>,
    /// Why a forged inclusion path refuses the way it does for this receipt form.
    ///
    /// On an ATTACHED receipt the fold and the signature are separable, so a forged path
    /// is refused as an inclusion mismatch while the service's signature stays valid —
    /// which is what shows SCITT receipt verification rather than mere COSE signature
    /// checking. On a DETACHED receipt they are one check by construction, because the
    /// fold's output IS the signed payload; the refusal is then a signature failure and
    /// cannot be exhibited with a valid signature.
    pub(super) refusal_note: String,
}

/// Whether a tagged `COSE_Sign1`'s payload slot is CBOR `null` — the detached form.
/// Read from the octets rather than from a parsed view, so it reports what is on the wire.
fn cbor_payload_is_absent(receipt: &[u8]) -> bool {
    Receipt::from_cose(receipt).expect("receipt parses");
    // The payload is the third element; `f6` is CBOR null. Scanning for the marker that
    // precedes the 64-octet signature (`58 40`) keeps this independent of header sizes.
    receipt.windows(3).any(|w| w == [0xf6, 0x58, 0x40])
}

fn digest_of(bytes: &[u8]) -> String {
    use sha2::Digest;
    mcp_re_core::b64url_encode(&sha2::Sha256::digest(bytes))
}

/// Every leaf rule this verifier implements, by the token a pin writes.
///
/// Enumerated once, here, so a fourth reading of RFC 9162 §2.1's entry cannot be added to
/// the profile without the reports that exercise the wrong ones noticing.
const LEAF_PROFILE_TOKENS: &[&str] = &[
    "statement-bytes",
    "statement-digest",
    "sig-structure-digest",
];

/// The token a pin writes for a leaf profile.
fn leaf_profile_token(profile: mcp_re_http_profile::scitt::StatementLeafProfile) -> &'static str {
    use mcp_re_http_profile::scitt::StatementLeafProfile as P;
    match profile {
        P::StatementBytes => "statement-bytes",
        P::StatementDigest => "statement-digest",
        P::SigStructureDigest => "sig-structure-digest",
    }
}

/// Verdict as the report records it: `verify_ok` or the wire code.
fn verdict_token(outcome: Result<(), HttpProfileError>) -> String {
    match outcome {
        Ok(()) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}

/// The artifacts one corpus directory holds, read by name.
struct CorpusDir<'a>(&'a std::path::Path);

impl CorpusDir<'_> {
    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }
}

/// What one corpus is verified from: its statement, its receipt and its pinned service key.
struct Subject {
    statement: SignedStatement,
    receipt: Receipt,
    pin: ScittServiceTrustPin,
}

impl Subject {
    fn load(corpus: &CorpusDir<'_>) -> Self {
        Subject {
            statement: SignedStatement::from_cose(&corpus.read("signed-statement.cbor"))
                .expect("statement"),
            receipt: Receipt::from_cose(&corpus.read("receipt.cbor")).expect("receipt"),
            pin: serde_json::from_slice(&corpus.read("service-key-pin.json")).expect("pin"),
        }
    }

    /// The verdict of verifying this corpus's receipt under `pin`.
    fn verdict_under(&self, pin: &ScittServiceTrustPin) -> String {
        verdict_token(verify_with(&self.statement, &self.receipt, pin))
    }
}

/// Artifact name → base64url SHA-256, over the bytes on disk.
fn artifact_digests(corpus: &CorpusDir<'_>) -> std::collections::BTreeMap<String, String> {
    [
        "signed-statement.cbor",
        "receipt.cbor",
        "retained-evidence.bin",
        "service-key-pin.json",
        "exchange-metadata.json",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), digest_of(&corpus.read(name))))
    .collect()
}

/// The refusals reached by editing the pin: the wrong key, a pin for another kid, and every
/// leaf profile this verifier implements except the pinned one.
fn pin_refusals(subject: &Subject, pin_bytes: &[u8]) -> Vec<(String, String)> {
    let mut refusals = Vec::new();

    // A pinned key that is not the signer.
    let wrong_key = pin_document_with(pin_bytes, |d| {
        d["public_key"]["x"] = another_ed25519_key();
    });
    refusals.push((
        "wrong-pinned-service-key".to_owned(),
        subject.verdict_under(&wrong_key),
    ));

    // A pin that answers for a different kid.
    let wrong_kid = pin_document_with(pin_bytes, |d| {
        d.insert("kid".into(), "not-the-receipts-kid".into());
    });
    refusals.push((
        "kid-not-covered-by-the-pin".to_owned(),
        subject.verdict_under(&wrong_kid),
    ));

    // EVERY leaf profile this verifier implements except the pinned one. Exactly one can
    // be right, and with three readings of "the entry" in the registry the singular "the
    // other profile" stopped being a well-formed question: a report that exercised one of
    // the two wrong ones would leave the other unexercised and look the same.
    for wrong in LEAF_PROFILE_TOKENS
        .iter()
        .filter(|token| **token != leaf_profile_token(subject.pin.leaf_profile()))
    {
        let wrong_profile = pin_document_with(pin_bytes, |d| {
            d.insert("leaf_profile".into(), (*wrong).into());
        });
        refusals.push((
            format!("wrong-leaf-profile:{wrong}"),
            subject.verdict_under(&wrong_profile),
        ));
    }
    refusals
}

/// The octet offset of the first sibling hash in the unprotected inclusion path, when the
/// receipt carries one in the expected CBOR shape.
fn inclusion_path_offset(bytes: &[u8]) -> Option<usize> {
    (0..bytes.len().saturating_sub(6)).find(|&i| {
        bytes[i] == 0x83 && bytes[i + 3] == 0x81 && bytes[i + 4] == 0x58 && bytes[i + 5] == 0x20
    })
}

/// A sibling hash flipped in the unprotected inclusion path — the service's own
/// signature stays valid, so only the fold refuses it.
fn forged_path_refusal(subject: &Subject, receipt_bytes: &[u8]) -> Option<(String, String)> {
    let at = inclusion_path_offset(receipt_bytes)?;
    let mut forged = receipt_bytes.to_vec();
    forged[at + 6 + 31] ^= 0x01;
    let outcome =
        Receipt::from_cose(&forged).and_then(|r| verify_with(&subject.statement, &r, &subject.pin));
    Some((
        "forged-inclusion-path-valid-service-signature".to_owned(),
        verdict_token(outcome),
    ))
}

/// Why a forged inclusion path refuses the way it does for this receipt form.
fn refusal_note(detached: bool) -> String {
    if detached {
            "detached payload: the re-derived root IS the signed payload, so a forged              inclusion path is refused as a signature failure — the fold and the              signature are one check and cannot be separated"
    } else {
            "attached payload: a forged inclusion path is refused as an inclusion              mismatch while the service's signature remains valid — the fold is doing              the work, not the signature check"
    }
    .to_owned()
}

/// Build the report for one corpus directory by actually running the verification.
pub(super) fn build_report(dir: &std::path::Path, peer: &str) -> VerificationReport {
    let corpus = CorpusDir(dir);
    let subject = Subject::load(&corpus);
    let receipt_bytes = corpus.read("receipt.cbor");
    let refusals = pin_refusals(&subject, &corpus.read("service-key-pin.json"))
        .into_iter()
        .chain(forged_path_refusal(&subject, &receipt_bytes))
        .collect();

    VerificationReport {
        schema: "mcp-re-scitt-verification-report/v1".to_owned(),
        peer: peer.to_owned(),
        verifier:
            "mcp-re-http-profile::scitt::verify_receipt_offline (offline; no service contacted)"
                .to_owned(),
        generated_by: "mcp-re-conformance/tests/scitt_interop_test.rs::write_verification_reports"
            .to_owned(),
        artifacts: artifact_digests(&corpus),
        positive_verdict: subject.verdict_under(&subject.pin),
        refusals,
        // Whether this service emits detached receipts decides how a forged path refuses.
        refusal_note: refusal_note(cbor_payload_is_absent(&receipt_bytes)),
    }
}

pub(super) fn corpora() -> Vec<(PathBuf, String)> {
    let transmute: serde_json::Value =
        serde_json::from_slice(&artifact("manifest.json")).expect("manifest");
    let capsule: serde_json::Value =
        serde_json::from_slice(&capsule("manifest.json")).expect("manifest");
    let operated: serde_json::Value =
        serde_json::from_slice(&operated_capsule("manifest.json")).expect("manifest");
    vec![
        (
            interop_dir(),
            transmute["peer"].as_str().expect("peer").to_owned(),
        ),
        (
            capsule_dir(),
            capsule["peer"].as_str().expect("peer").to_owned(),
        ),
        (
            operated_capsule_dir(),
            operated["peer"].as_str().expect("peer").to_owned(),
        ),
    ]
}
