// SPDX-License-Identifier: Apache-2.0
//! Admission vectors (#414 §4.3/§5, #415 §7, MCPRE-433).
//!
//! Each freezes the assertion JWS, the call's binding, and the authoritative snapshot, so
//! the §7 currency verdict is deterministic. The load-bearing one (h43) freezes a signed,
//! fresh, "admitted" assertion that is STILL refused because the authoritative generation
//! moved on — a snapshot is not currency.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::ActorIdentity;

use super::material::CLIENT_KEY_ID;
use super::material::NOW;
use super::schema::AdmissionCheck;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

pub(super) const ISSUER_KID: &str = "admission-root-1";

fn admission_root() -> SigningKey {
    SigningKey::from_seed_bytes(&[44u8; 32])
}

/// The verifier-resolved actor id an admission assertion must name.
pub(super) fn admission_presenter() -> String {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:client".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id()
}

fn admission_claims(
    generation: u64,
    status: mcp_re_http_profile::AdmissionStatus,
) -> mcp_re_http_profile::AdmissionClaims {
    use sha2::Digest;
    mcp_re_http_profile::AdmissionClaims {
        iss: "did:example:admission".into(),
        iat: NOW - 10,
        nbf: NOW - 10,
        exp: NOW + 300,
        jti: format!("adm#{generation}"),
        aud: mcp_re_http_profile::Audience::One("mcp.example.com".into()),
        mcp_re_profile: mcp_re_http_profile::PROFILE_TAG.into(),
        mcp_re_admission_id: "workload-7".into(),
        // The actor the assertion is issued TO. Without it an assertion is a bearer
        // token any verifying peer can present.
        mcp_re_admitted_actor: admission_presenter(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: mcp_re_core::b64url_encode(&sha2::Sha256::digest(
            b"admitted-state",
        )),
        mcp_re_admission_status: status,
        issuer_kid: ISSUER_KID.into(),
    }
}

/// What the PEP's authoritative state says about the workload, and how far a missing
/// state may be tolerated.
struct Authority<'a> {
    state: Option<(u64, &'a str)>,
    degraded_bound: Option<i64>,
}

fn admission_fixture(
    name: &str,
    claims: &mcp_re_http_profile::AdmissionClaims,
    authority: &Authority<'_>,
    expected: &str,
) -> Fixture {
    let jws = mcp_re_http_profile::issue_admission_assertion(claims, |input| {
        mcp_re_core::b64url_decode(&admission_root().sign(input))
            .map_err(|_| mcp_re_http_profile::HttpProfileError::InvalidSignature)
    })
    .expect("issue");
    let binding = mcp_re_http_profile::AdmissionBinding::opaque_from(claims);
    Fixture {
        admission_check: Some(AdmissionCheck {
            assertion_jws: jws,
            binding: serde_json::to_value(&binding).expect("binding serializes"),
            authoritative_generation: authority.state.map(|(g, _)| g),
            authoritative_status: authority.state.map(|(_, s)| s.to_owned()),
            issuer_public_key_b64url: admission_root().public_key().to_b64url(),
            allow_degraded_mode: authority.degraded_bound.is_some(),
            degraded_propagation_bound: authority.degraded_bound.unwrap_or(0),
        }),
        ..Vector {
            name,
            kind: Kind::Admission,
            expected,
        }
        .blank()
    }
}

/// h42–h46: a current admitted workload is served; a stale generation, a revocation and
/// an unreachable authority are refused; an unreachable authority within the degraded
/// bound is served.
pub(super) fn admission_fixtures() -> Vec<Fixture> {
    use mcp_re_http_profile::AdmissionStatus::Admitted;
    let vector = |name: &str, authority: Authority<'_>, expected: &str| {
        admission_fixture(name, &admission_claims(5, Admitted), &authority, expected)
    };
    let stated = |generation, status| Authority {
        state: Some((generation, status)),
        degraded_bound: None,
    };
    let refused = "mcp-re.actor_binding_failed";
    vec![
        // h42 — current admitted workload: served.
        vector(
            "h42_admission_current_admitted",
            stated(5, "admitted"),
            "verify_ok",
        ),
        // h43 — the load-bearing case: a valid, fresh, admitted assertion refused
        //       because the authoritative generation advanced. A snapshot is not currency.
        vector(
            "h43_admission_stale_generation",
            stated(6, "admitted"),
            refused,
        ),
        // h44 — revoked after issuance.
        vector(
            "h44_admission_revoked_after_issuance",
            stated(5, "revoked"),
            refused,
        ),
        // h45 — authoritative state unreachable, degraded disabled: fail closed.
        vector(
            "h45_admission_state_unreachable_failclosed",
            Authority {
                state: None,
                degraded_bound: None,
            },
            refused,
        ),
        // h46 — unreachable state within the P bound with degraded enabled: served.
        vector(
            "h46_admission_degraded_within_bound",
            Authority {
                state: None,
                degraded_bound: Some(600),
            },
            "verify_ok",
        ),
    ]
}
