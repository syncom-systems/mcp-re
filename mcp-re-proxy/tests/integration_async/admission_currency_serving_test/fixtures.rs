// SPDX-License-Identifier: Apache-2.0
//! The keys, identities and signed material the admission-currency batteries run on.
//!
//! Everything here is a statement about WHO signs WHAT: the client's request key, the
//! response-signing root, and the admission authority's own root — three different keys, so
//! "trusted to sign responses" can never be mistaken for "trusted to admit".

use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::authoritative_admission::record::issue_admission_state_record;
use mcp_re_http_profile::authoritative_admission::record::AdmissionStateClaims;
use mcp_re_http_profile::authoritative_admission::record::AdmissionStateCurrentness;
use mcp_re_http_profile::issue_admission_assertion;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::admission_source::AdmissionRecordVerifier;
use mcp_re_proxy::admission_source::InMemoryAdmissionSource;
use mcp_re_proxy::http_profile_serve::AdmissionAuthorityResolver;
use mcp_re_proxy::ActorResolver;
use sha2::Digest;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const AUTHORITY_SEED: [u8; 32] = [44u8; 32];
pub(super) const NOW: i64 = 1_700_000_100;
pub(super) const CREATED: i64 = 1_700_000_000;
pub(super) const EXPIRES: i64 = 1_700_000_300;
pub(super) const TARGET: &str = "https://mcp.example.com/mcp?route=a";
pub(super) const CLIENT_KEY_ID: &str = "client-key-1";
pub(super) const ROOT_KID: &str = "root-kid";
pub(super) const AUTHORITY_KID: &str = "admission-root-1";
pub(super) const VERIFIER_AUD: &str = "verifier-1";
pub(super) const WORKLOAD: &str = "workload-7";

/// What an admission refusal looks like ON THE WIRE.
///
/// Not `mcp-re.admission_not_current`: no such token exists, deliberately. The
/// taxonomy is frozen and every wire code is a core token, so an admission failure
/// collapses onto `actor_binding_failed` — the caller is not authorized to act, which
/// is the true statement the client can act on.
///
/// The cost is real and worth naming: a revoked workload, an unknown one, and an
/// authority outage are indistinguishable to the client, and to an operator reading
/// only the wire code. That is why the propagation harness below measures the
/// TRANSITION from served to refused under a single changing variable rather than
/// keying off the code.
pub(super) const ADMISSION_REFUSED: &str = "mcp-re.actor_binding_failed";
/// A `Required` call that carried no admission evidence at all.
pub(super) const ABSENT_ADMISSION_EVIDENCE: &str = "mcp-re.missing_envelope";

/// The DEPLOYMENT's declared currentness budget for an authoritative record.
///
/// Wide enough that the record's own window is never what these batteries measure — they
/// are about the currency comparison and the degraded fork, and a record expiring underneath
/// them would make every one of them pass for the wrong reason. The budget's own boundary is
/// measured where it is decided, in `admission_state_record::currentness`.
pub(super) const RECORD_MAX_AGE: i64 = 3_600;

pub(super) fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

pub(super) fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}

/// The ADMISSION AUTHORITY's root — a different key from the response-signing root,
/// so "trusted to sign responses" can never be mistaken for "trusted to admit".
pub(super) fn authority_key() -> SigningKey {
    SigningKey::from_seed_bytes(&AUTHORITY_SEED)
}

pub(super) fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

pub(super) fn actor_resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        let (role, subject, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => {
                ("client", "did:example:host-a", client_key().public_key())
            }
            (ROOT_KID, SignerSlot::Response) => {
                ("server", "did:example:server", root_key().public_key())
            }
            _ => return None::<ResolvedActor>.into(),
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
        .into()
    })
}

/// Resolves ONLY the configured admission authority. Anything else is untrusted —
/// a kid never introduces trust.
pub(super) fn authority_resolver() -> AdmissionAuthorityResolver {
    Arc::new(|kid: &str| (kid == AUTHORITY_KID).then(|| authority_key().public_key()))
}

/// The actor id the PEP's verifier resolves for the signing client — the value an
/// assertion must name so it cannot be presented by anyone else.
fn client_actor_id() -> String {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:host-a".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id()
}

/// A store that will act on records signed by [`authority_key`] and no other.
pub(super) fn admission_store() -> InMemoryAdmissionSource {
    InMemoryAdmissionSource::new(AdmissionRecordVerifier::new(
        authority_resolver(),
        PROFILE_TAG,
        AdmissionStateCurrentness {
            max_record_age: RECORD_MAX_AGE,
            max_clock_skew: 30,
        },
    ))
}

/// The claims of an authority record for `admission_id`, inside its currentness budget.
pub(super) fn state_claims(
    admission_id: &str,
    generation: u64,
    revision: u64,
    status: AdmissionStatus,
) -> AdmissionStateClaims {
    AdmissionStateClaims {
        iss: "did:example:admission".into(),
        iat: NOW,
        nbf: NOW,
        exp: NOW + RECORD_MAX_AGE,
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: admission_id.into(),
        mcp_re_admission_generation: generation,
        mcp_re_admission_status: status,
        mcp_re_state_revision: revision,
        issuer_kid: AUTHORITY_KID.into(),
    }
}

/// `claims`, signed by `signer`. Whether the store will act on the result is the store's
/// business: a signer other than [`authority_key`] still produces well-formed bytes.
pub(super) fn sign_state_record(claims: &AdmissionStateClaims, signer: &SigningKey) -> String {
    issue_admission_state_record(claims, |input| {
        b64url_decode(&signer.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("a state record is issued for these claims")
}

/// The AUTHORITY's statement about a workload, signed and published.
///
/// Every publication advances the revision, because that is what a publication is; the
/// generation moves only when the admitted configuration does. The two counters are
/// deliberately independent here for the same reason they are in the record.
fn publish_state(
    source: &InMemoryAdmissionSource,
    generation: u64,
    revision: u64,
    status: AdmissionStatus,
) {
    let claims = state_claims(WORKLOAD, generation, revision, status);
    source.publish(WORKLOAD, sign_state_record(&claims, &authority_key()));
}

/// The authority admits the workload at `generation` — publication 1.
///
/// Deliberately not named for the Verus proof escape hatch that would shadow it:
/// `tools/verification/_seams.py` matches that mechanism in its code form, and a test
/// helper spelled the same way is indistinguishable from a real one to the gate whose job
/// is to notice unregistered seams. A gate that cannot tell them apart is one someone
/// eventually silences.
pub(super) fn publish_admitted(source: &InMemoryAdmissionSource, generation: u64) {
    publish_state(source, generation, 1, AdmissionStatus::Admitted);
}

/// The authority revokes, KEEPING the generation and advancing the publication.
pub(super) fn revoke(source: &InMemoryAdmissionSource, generation: u64) {
    publish_state(source, generation, 2, AdmissionStatus::Revoked);
}

/// A store in which the authority has admitted the workload at `generation`.
pub(super) fn admitted_source(generation: u64) -> Arc<InMemoryAdmissionSource> {
    let source = Arc::new(admission_store());
    publish_admitted(&source, generation);
    source
}

pub(super) fn admission_claims(
    generation: u64,
    status: AdmissionStatus,
    iat: i64,
) -> AdmissionClaims {
    AdmissionClaims {
        iss: "did:example:admission".into(),
        iat,
        nbf: iat,
        exp: iat + 600,
        jti: format!("adm#{generation}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: WORKLOAD.into(),
        mcp_re_admitted_actor: client_actor_id(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: b64url_encode(&sha2::Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: status,
        issuer_kid: AUTHORITY_KID.into(),
    }
}

/// The assertion an `Admitted` workload presents at `generation`, issued at the fixture clock.
pub(super) fn admitted_claims(generation: u64) -> AdmissionClaims {
    admission_claims(generation, AdmissionStatus::Admitted, CREATED)
}

pub(super) fn issue_assertion(claims: &AdmissionClaims, signer: &SigningKey) -> String {
    issue_admission_assertion(claims, |input| {
        b64url_decode(&signer.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue")
}
