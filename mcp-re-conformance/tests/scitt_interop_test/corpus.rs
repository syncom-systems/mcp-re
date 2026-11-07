// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! The committed interop corpora and the fixtures read from them.

use std::path::PathBuf;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::chain::ChainLabel;
use mcp_re_http_profile::chain::ChainReconstruction;
use mcp_re_http_profile::chain::HopEvidence;
use mcp_re_http_profile::evidence::RequestRoleEvidence;
use mcp_re_http_profile::evidence::ResponseRoleEvidence;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;

/// The committed corpus directory: the runfile the manifest variable names under Bazel, or
/// the source tree otherwise.
pub(super) fn interop_dir() -> PathBuf {
    match std::env::var("MCP_RE_SCITT_INTEROP_MANIFEST") {
        Ok(rel) => manifest_dir(&rel),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("vectors")
            .join("scitt")
            .join("interop"),
    }
}

/// The directory holding the manifest `rel` names, searched under each runfiles root and
/// then as a plain path.
fn manifest_dir(rel: &str) -> PathBuf {
    let under_runfiles = ["TEST_SRCDIR", "RUNFILES_DIR"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|root| std::path::Path::new(&root).join(rel));
    under_runfiles
        .chain(std::iter::once(PathBuf::from(rel)))
        .find(|candidate| candidate.exists())
        .map(|candidate| candidate.parent().expect("manifest parent").to_path_buf())
        .unwrap_or_else(|| {
            panic!("MCP_RE_SCITT_INTEROP_MANIFEST set but runfile not found (rel={rel})")
        })
}

pub(super) fn artifact(name: &str) -> Vec<u8> {
    std::fs::read(interop_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Parse `retained-evidence.bin` into the chain reconstruction an auditor would hold.
///
/// The artifact records EVERY hop's signature bases, because the statement's
/// `chain_commitment` covers every hop: a retained set that stopped at hop 0 could not
/// reproduce it.
///
/// It records HANDLES, not the submitted messages, so the submission digest is not
/// reproducible from it and the record identifies no submission.
/// [`ChainReconstruction::from_retained_handles`] is how a reconstruction says that, and
/// it is the only producer that can: the identity field is private, so this corpus cannot
/// author one it never computed. That limit is what
/// `a_statement_identifying_no_submission_binds_no_retained_record` records.
pub(super) fn retained_chain(bytes: &[u8]) -> ChainReconstruction {
    let retained: serde_json::Value = serde_json::from_slice(bytes).expect("retained parses");
    assert_eq!(
        retained["chain_label"].as_str(),
        Some("complete"),
        "the corpus record is a complete chain"
    );
    ChainReconstruction::from_retained_handles(
        ChainLabel::Complete,
        retained["hops"]
            .as_array()
            .expect("hops")
            .iter()
            .map(|hop| HopEvidence {
                request_evidence: RequestRoleEvidence::from_signature_base(
                    hop["request"].as_str().expect("request base").as_bytes(),
                ),
                response_evidence: ResponseRoleEvidence::from_signature_base(
                    hop["response"].as_str().expect("response base").as_bytes(),
                ),
            })
            .collect(),
    )
}

pub(super) fn pin() -> ScittServiceTrustPin {
    serde_json::from_slice(&artifact("service-key-pin.json")).expect("pin parses")
}

/// The corpus pin with one field of its DOCUMENT edited.
///
/// The edit is applied to the JSON, not to a parsed pin, because a pin no longer has
/// editable fields: its `(algorithm, public_key)` pair is checked on the way in, so the
/// only way to obtain a different one is to present a different document. That is also
/// the more faithful negative fixture — a pin an operator could ship by mistake, rather
/// than a value that could only ever have existed in memory.
pub(super) fn pin_document_with(
    bytes: &[u8],
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> ScittServiceTrustPin {
    let mut document: serde_json::Value = serde_json::from_slice(bytes).expect("pin document");
    edit(
        document
            .as_object_mut()
            .expect("a pin document is an object"),
    );
    serde_json::from_value(document).expect("the edited document is still a legal pin")
}

/// A real Ed25519 key that is simply not the service's signer.
pub(super) fn another_ed25519_key() -> serde_json::Value {
    mcp_re_core::b64url_encode(
        &mcp_re_core::SigningKey::from_seed_bytes(&[0xAB; 32])
            .public_key()
            .to_bytes(),
    )
    .into()
}

pub(super) fn statement() -> SignedStatement {
    SignedStatement::from_cose(&artifact("signed-statement.cbor")).expect("statement parses")
}

pub(super) fn receipt() -> Receipt {
    Receipt::from_cose(&artifact("receipt.cbor")).expect("receipt parses")
}

/// The statement's issuer key — our own corpus issuer, since MCP-RE issued the statement.
pub(super) fn issuer() -> VerificationKey {
    let s01: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            interop_dir()
                .parent()
                .expect("scitt dir")
                .join("s01_complete_record.json"),
        )
        .expect("s01 committed"),
    )
    .expect("s01 parses");
    VerificationKey::from_b64url(s01["issuer_pubkey_b64url"].as_str().expect("issuer key"))
        .expect("issuer key decodes")
}

pub(super) fn verify_with(
    statement: &SignedStatement,
    receipt: &Receipt,
    pin: &ScittServiceTrustPin,
) -> Result<(), HttpProfileError> {
    let issuer = issuer();
    verify_receipt_offline(
        statement,
        receipt,
        |_| Some(issuer.clone().into()),
        |kid| pin.resolve(kid),
    )
}

/// Verify the receipt of the corpus `read` serves: its statement, its receipt and its
/// pinned service key, parsed from the committed octets.
pub(super) fn verify_corpus(read: fn(&str) -> Vec<u8>) -> Result<(), HttpProfileError> {
    let statement = SignedStatement::from_cose(&read("signed-statement.cbor")).expect("parses");
    let receipt = Receipt::from_cose(&read("receipt.cbor")).expect("parses");
    let pin: ScittServiceTrustPin =
        serde_json::from_slice(&read("service-key-pin.json")).expect("pin parses");
    verify_with(&statement, &receipt, &pin)
}

/// The corpus from the `capsule-anchor` exchange: it accepted our exact Signed Statement
/// over HTTP and returned a receipt. Frozen so verification is reproducible with the
/// service stopped — which is what "offline" has to mean.
pub(super) fn capsule_dir() -> PathBuf {
    interop_dir().join("capsule-anchor")
}

pub(super) fn capsule(name: &str) -> Vec<u8> {
    std::fs::read(capsule_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The frozen exchange with the OPERATED instance.
pub(super) fn operated_capsule_dir() -> PathBuf {
    interop_dir().join("capsule-anchor-live")
}

pub(super) fn operated_capsule(name: &str) -> Vec<u8> {
    std::fs::read(operated_capsule_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}
