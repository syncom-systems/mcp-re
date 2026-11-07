// SPDX-License-Identifier: Apache-2.0
//! The fixed keys, identities and statements every vector is built from.

use std::path::Path;
use std::path::PathBuf;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::chain::ChainLabel;
use mcp_re_http_profile::chain::ChainReconstruction;
use mcp_re_http_profile::chain::HopEvidence;
use mcp_re_http_profile::scitt::issue_signed_statement;
use mcp_re_http_profile::scitt::EvidenceCommitment;
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::ResponseRoleEvidence;

pub(super) const ISSUER_KID: &str = "scitt-issuer-1";
pub(super) const TS_KID: &str = "scitt-ts-1";
pub(super) const ISSUED_AT: i64 = 1_700_000_000;

pub(super) fn issuer() -> SigningKey {
    SigningKey::from_seed_bytes(&[55u8; 32])
}
pub(super) fn ts() -> SigningKey {
    SigningKey::from_seed_bytes(&[66u8; 32])
}
/// A real Ed25519 key from a different seed — for the untrusted-issuer vector. A
/// MALFORMED key would be refused as bad configuration and would prove nothing about
/// the trust decision.
pub(super) fn stranger() -> SigningKey {
    SigningKey::from_seed_bytes(&[77u8; 32])
}

/// The corpus directory: the runfiles copy under Bazel, the source tree otherwise.
///
/// Bazel runs tests in a sandbox where `CARGO_MANIFEST_DIR` is not the source tree, so
/// the manifest's runfile path is passed in. Mirrors `delegation_vectors_test`.
pub(super) fn vectors_root() -> PathBuf {
    let Ok(rel) = std::env::var("MCP_RE_SCITT_VECTORS_MANIFEST") else {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("vectors")
            .join("scitt");
    };
    let found = runfile_candidates(&rel).into_iter().find(|c| c.exists());
    match found {
        Some(candidate) => candidate.parent().expect("manifest parent").to_path_buf(),
        None => panic!("MCP_RE_SCITT_VECTORS_MANIFEST set but runfile not found (rel={rel})"),
    }
}

/// Where the manifest's runfile may live: under each runfiles root, then as given.
fn runfile_candidates(rel: &str) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = ["TEST_SRCDIR", "RUNFILES_DIR"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|root| Path::new(&root).join(rel))
        .collect();
    candidates.push(PathBuf::from(rel));
    candidates
}

fn reconstruction(label: ChainLabel, hops: usize) -> ChainReconstruction {
    ChainReconstruction::with_authored_submission_identity(
        label,
        (0..hops)
            .map(|i| HopEvidence {
                request_evidence: RequestRoleEvidence::from_signature_base(
                    format!("req-{i}").as_bytes(),
                ),
                response_evidence: ResponseRoleEvidence::from_signature_base(
                    format!("rsp-{i}").as_bytes(),
                ),
            })
            .collect(),
        // A synthetic corpus fixture: the vectors pin the encoding of a commitment, not
        // the bytes of a real submission, so this is a stable stand-in rather than a
        // digest of hops that do not exist here.
        format!("corpus-submitted-{hops}"),
    )
}

/// The commitment to a `hops`-hop chain carrying `label`.
pub(super) fn commitment(label: ChainLabel, hops: usize) -> EvidenceCommitment {
    EvidenceCommitment::from_reconstruction(&reconstruction(label, hops), None, None)
}

/// A statement from the corpus issuer committing to `commitment`.
pub(super) fn statement(commitment: EvidenceCommitment) -> SignedStatement {
    statement_by(ISSUER_KID, commitment, &issuer())
}

/// A statement naming `kid`, signed with `key`.
pub(super) fn statement_by(
    kid: &str,
    commitment: EvidenceCommitment,
    key: &SigningKey,
) -> SignedStatement {
    issue_signed_statement(kid, commitment, ISSUED_AT, |input| {
        b64url_decode(&key.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue")
}

/// The transparency service's tree-head signer. A fn item rather than a closure so it
/// can be handed to more than one `register` call.
fn sign_tree_head(head: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    b64url_decode(&ts().sign(head)).map_err(|_| HttpProfileError::InvalidSignature)
}

/// A log of `fillers` unrelated entries, which the next registration lands after.
pub(super) fn log_with_fillers(fillers: usize) -> PrototypeTransparencyService {
    let mut svc = PrototypeTransparencyService::new(TS_KID);
    for i in 0..fillers {
        let filler = statement(commitment(ChainLabel::Complete, 4 + i));
        svc.register(&filler, sign_tree_head).expect("filler entry");
    }
    svc
}

/// Register `target` in `svc` and return its receipt.
pub(super) fn register_in(
    svc: &mut PrototypeTransparencyService,
    target: &SignedStatement,
) -> Receipt {
    svc.register(target, sign_tree_head).expect("register")
}

/// Register `statement` into a log that already holds one unrelated entry, and return
/// its receipt.
///
/// The preceding entry is not decoration. A single-leaf log yields an EMPTY inclusion
/// path, which `inclusion-path = [ + bstr ]` (RFC 9942 §5.2, Figure 3) does not admit
/// and which exercises no folding at all — the leaf would be the root. With a sibling
/// present, every vector pins a proof that actually has to be walked.
pub(super) fn register(statement: &SignedStatement) -> Receipt {
    register_in(&mut log_with_fillers(1), statement)
}
