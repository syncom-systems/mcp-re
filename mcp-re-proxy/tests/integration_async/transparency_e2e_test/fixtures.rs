// SPDX-License-Identifier: Apache-2.0
//! The fixed identities, scratch storage and verification seams every lane of the
//! transparency vertical shares.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::scitt::CoseVerificationKey;
use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::ReceiptPositionProfile;
use mcp_re_http_profile::scitt::ResolvedTransparencyService;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::scitt::StatementLeafProfile;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_proxy::transparency::attest_chain;
use mcp_re_proxy::transparency::Attestation;
use mcp_re_proxy::transparency::EvidenceRetention;
use mcp_re_proxy::transparency::RetainedArchive;
use mcp_re_proxy::ActorResolver;
use std::sync::Arc;

pub(super) const CLIENT_SEED: [u8; 32] = [11u8; 32];
pub(super) const ROOT_SEED: [u8; 32] = [55u8; 32];
pub(super) const ISSUER_SEED: [u8; 32] = [77u8; 32];
pub(super) const TS_SEED: [u8; 32] = [88u8; 32];
pub(super) const NOW: i64 = 1_700_000_100;
pub(super) const TARGET: &str = "https://mcp.example.com/mcp?route=a";
pub(super) const CLIENT_KEY_ID: &str = "client-key-1";
pub(super) const ROOT_KID: &str = "root-kid";
pub(super) const ISSUER_KID: &str = "pep-statement-issuer";
pub(super) const TS_KID: &str = "prototype-ts";
pub(super) const AUD: &str = "verifier-1";
pub(super) const EPOCH: &str = "epoch-1";
pub(super) const ACCESS_TOKEN: &str = "access-token-xyz";

pub(super) fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
pub(super) fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
pub(super) fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ISSUER_SEED)
}
pub(super) fn ts_key() -> SigningKey {
    SigningKey::from_seed_bytes(&TS_SEED)
}

pub(super) struct Scratch(std::path::PathBuf);

impl Scratch {
    pub(super) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-re-transparency-e2e-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        Scratch(path)
    }
    pub(super) fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
    /// The retained evidence as an auditor reads it: a read-only archive over the directory.
    pub(super) fn archive(&self) -> RetainedArchive {
        RetainedArchive::open_read_only(self.join("evidence")).expect("open the archive")
    }
    /// A retention store over this scratch's `evidence` directory.
    pub(super) fn retention(&self) -> Arc<EvidenceRetention> {
        Arc::new(EvidenceRetention::open(self.join("evidence")).expect("open retention"))
    }
    /// The names of everything the evidence directory holds, in directory order.
    pub(super) fn retained_names(&self) -> Vec<String> {
        std::fs::read_dir(self.join("evidence"))
            .expect("the store directory exists")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }
    /// The digest of the retained object stored under `name`.
    pub(super) fn digest_of(&self, name: &str) -> EvidenceDigest {
        EvidenceDigest::of(&std::fs::read(self.join("evidence").join(name)).expect("read back"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The trust seam for BOTH the serving path (Request slot) and the auditor's
/// reconstruction (Response slot: the root the delegated credential chains to).
pub(super) fn resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:client".into(),
                    keyid: CLIENT_KEY_ID.into(),
                },
                verification_key: client_key().public_key(),
                slot,
            }),
            (ROOT_KID, SignerSlot::Response) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "mcp.example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: ROOT_KID.into(),
                },
                verification_key: root_key().public_key(),
                slot,
            }),
            _ => None,
        }
        .into()
    })
}

/// A resolver that resolves nobody: hop 0's request cannot be verified, so a
/// reconstruction through it has an empty verified prefix.
pub(super) fn nobody() -> ActorResolver {
    Box::new(|_key_id: &str, _slot: SignerSlot| Option::<ResolvedActor>::None.into())
}

/// The full-profile audit inputs for reconstruction: the verifier's own audience tuple
/// and the DPoP credential surface the retained request does not carry.
fn attest_audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn attest_material(_: &mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> {
    Some(ACCESS_TOKEN.as_bytes().to_vec())
}

static ATTEST_MATERIAL: fn(&mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> =
    attest_material;

pub(super) fn attest_audit() -> mcp_re_http_profile::ChainAudit<'static> {
    static AUDIENCE: std::sync::OnceLock<AudienceTuple> = std::sync::OnceLock::new();
    mcp_re_http_profile::ChainAudit {
        expected_audience: AUDIENCE.get_or_init(attest_audience),
        artifact_material: &ATTEST_MATERIAL,
    }
}

pub(super) fn expectations<'a>(
    audiences: &'a [&'a str],
    epochs: &'a [&'a str],
) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: audiences,
        expected_audience_hash: AUD,
        accepted_epochs: epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

/// The external-signer seam COSE issuance and registration take: raw signature bytes,
/// so the issuer/TS key never enters the profile crate.
pub(super) fn sign_with(key: SigningKey) -> impl Fn(&[u8]) -> Result<Vec<u8>, HttpProfileError> {
    move |preimage: &[u8]| {
        mcp_re_core::b64url_decode(&key.sign(preimage))
            .map_err(|_| HttpProfileError::InvalidSignature)
    }
}

/// Attest `hops` from `scratch`'s archive, judging the retained requests with `resolver`.
pub(super) fn attest(
    scratch: &Scratch,
    hops: &[EvidenceDigest],
    resolver: &ActorResolver,
) -> Result<Attestation, mcp_re_proxy::transparency::AttestError> {
    let audiences = [AUD];
    let epochs = [EPOCH];
    attest_chain(
        &scratch.archive(),
        hops,
        &Verifier::new(&VerifierPolicy::default(), resolver),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
}

/// Reconstruct the chain over `hops` from `scratch`'s archive, as an auditor holding only
/// the retained bytes would.
pub(super) fn reconstruct(
    scratch: &Scratch,
    hops: &[EvidenceDigest],
) -> mcp_re_http_profile::ChainReconstruction {
    let audiences = [AUD];
    let epochs = [EPOCH];
    let retained = scratch.archive().load_chain(hops).expect("load the chain");
    mcp_re_http_profile::reconstruct_chain(
        &retained,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
    )
}

/// The receipt for `statement` verifies offline, contacting nobody, against the
/// prototype log's key — issuer signature, inclusion proof and the service's signature
/// over the root.
pub(super) fn assert_verifies_offline_under_prototype(
    statement: &SignedStatement,
    receipt: &mcp_re_http_profile::scitt::Receipt,
    context: &str,
) {
    mcp_re_http_profile::scitt::verify_receipt_offline(
        statement,
        receipt,
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| {
            // `stated`, not a pin: this is the in-process prototype log, so there is no
            // operator-reviewed document to resolve the profiles from and the test says so.
            (kid == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    CoseVerificationKey::Ed25519(ts_key().public_key()),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        },
    )
    .expect(context);
}
