// SPDX-License-Identifier: Apache-2.0
//! The shared trust-anchor rotation scenario: signed manifests that move trust from one root to
//! another, and the credential verification each phase asserts against.

use super::RootAuthority;
use super::AUD;
use super::AUD_SCOPE;
use super::EPOCH;
use super::ORG_KID;
use super::SERVER_SIGNER;
use mcp_re_client_core::load_signed_manifest_with_floor;
use mcp_re_client_core::sign_manifest;
use mcp_re_client_core::DelegatedResponseTrust;
use mcp_re_client_core::InMemoryVersionFloor;
use mcp_re_client_core::LoadedTrustAnchors;
use mcp_re_client_core::ManifestIssuer;
use mcp_re_client_core::RetiringIssuer;
use mcp_re_client_core::RevocationSource;
use mcp_re_client_core::SignedTrustAnchorManifest;
use mcp_re_client_core::TrustAnchorManifest;
use mcp_re_client_core::TrustManifestError;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::verify_delegation_credential;
use mcp_re_http_profile::DelegationVerifyParams;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

fn org_resolver(
    signer_kid: &str,
    org_pub: VerificationKey,
) -> impl Fn(&str) -> Option<VerificationKey> {
    let kid = signer_kid.to_string();
    move |k: &str| {
        if k == kid {
            Some(org_pub.clone())
        } else {
            None
        }
    }
}

fn verify_params<'a>(now: i64) -> DelegationVerifyParams<'a> {
    DelegationVerifyParams {
        now,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
        verifier_audiences: &[AUD],
        expected_profile: PROFILE_TAG,
        expected_audience_hash: AUD_SCOPE,
        expected_server_signer: SERVER_SIGNER,
        accepted_epochs: &[EPOCH],
    }
}

/// Which roots a manifest names, and in which role.
struct Anchors {
    current: Vec<ManifestIssuer>,
    retiring: Vec<RetiringIssuer>,
    revoked: Vec<String>,
}

/// An org-signed manifest, and the version a verifier that has accepted it holds as its floor.
struct PublishedManifest<'a> {
    signed: SignedTrustAnchorManifest,
    version: u64,
    org_key: &'a SigningKey,
}

impl<'a> PublishedManifest<'a> {
    fn publish(version: u64, anchors: Anchors, now: i64, org_key: &'a SigningKey) -> Self {
        let manifest = TrustAnchorManifest {
            profile: PROFILE_TAG.into(),
            manifest_version: version,
            current_issuers: anchors.current,
            retiring_issuers: anchors.retiring,
            revoked_issuers: anchors.revoked,
            issued_at: now,
            expires_at: now + 100_000,
        };
        PublishedManifest {
            signed: sign_manifest(&manifest, org_key, ORG_KID),
            version,
            org_key,
        }
    }

    fn load_at_floor(
        &self,
        floor: u64,
        now: i64,
    ) -> Result<LoadedTrustAnchors, TrustManifestError> {
        load_signed_manifest_with_floor(
            &self.signed,
            org_resolver(ORG_KID, self.org_key.public_key()),
            PROFILE_TAG,
            &mut InMemoryVersionFloor::starting_at(floor),
            now,
        )
    }

    /// Verify a credential against the trust anchors this manifest loads at `now`.
    fn verify(&self, compact_jws: &str, now: i64) -> Result<(), HttpProfileError> {
        let set = self
            .load_at_floor(self.version, now)
            .expect("manifest loads")
            .issuer_set;
        verify_delegation_credential(
            compact_jws,
            &verify_params(now),
            // MCPRE-172: the public resolution interface, which already fails closed on a
            // revoked issuer. The raw lifecycle lookup is no longer reachable from here.
            |issuer_kid| {
                set.resolve_issuer(issuer_kid, SignerSlot::Response, now)
                    .resolved()
                    .map(|a| a.verification_key)
            },
            |id| set.is_revoked(id),
        )
        .map(|_| ())
    }

    fn assert_accepts(&self, compact_jws: &str, now: i64, why: &str) {
        self.verify(compact_jws, now).expect(why);
    }

    fn assert_refuses_untrusted_issuer(&self, compact_jws: &str, now: i64, why: &str) {
        assert_eq!(
            self.verify(compact_jws, now).unwrap_err(),
            HttpProfileError::DelegationIssuerUntrusted,
            "{why}"
        );
    }
}

/// # A note on the refusal CODE, for every root-revocation row below
///
/// Root revocation reports `delegation_issuer_untrusted`, not `delegation_revoked`.
///
/// The PROPOSITION is unchanged and is what these rows protect: revoking a root
/// invalidates every descendant delegated credential at once, before their own exp,
/// without chasing each delegated key. What changed under MCPRE-172 is where the refusal
/// happens. `TrustedIssuerSet::resolve_issuer` — the only public resolution interface —
/// fails closed on a revoked issuer BEFORE the credential's signature is reached, so a
/// revoked root can no longer yield a usable actor through any public path and cannot be
/// composed beside an empty revocation source.
///
/// The more precise code was only reachable while that composition was still possible.
/// A structural guarantee outranks a diagnostic distinction.
///
/// THE shared scenario: given two roots and an org manifest-signing key, drive the
/// full trust-anchor rotation — A-only → A+B overlap → B-only(A retired) → A revoked —
/// through SIGNED manifests, asserting acceptance/rejection at each phase. Run
/// identically by the in-memory (CI) and Cloud KMS (live) lanes.
pub fn run_rotation_scenario(root_a: &RootAuthority, root_b: &RootAuthority, org_key: &SigningKey) {
    let now = 1_700_000_100;
    let d1 = SigningKey::from_seed_bytes(&[91u8; 32]);
    let d2 = SigningKey::from_seed_bytes(&[92u8; 32]);
    let cred_a = root_a.issue_credential(&d1, 1, now);
    let cred_b = root_b.issue_credential(&d2, 1, now);

    // Phase 1 — manifest v1: Root A is the only trust anchor.
    let v1 = PublishedManifest::publish(
        1,
        Anchors {
            current: vec![root_a.as_manifest_issuer()],
            retiring: vec![],
            revoked: vec![],
        },
        now,
        org_key,
    );
    v1.assert_accepts(&cred_a, now, "A accepted under v1");
    v1.assert_refuses_untrusted_issuer(&cred_b, now, "B unknown under v1 (not yet introduced)");

    // Phase 2 — manifest v2: Root B introduced (current), Root A retiring in overlap.
    let overlap_until = now + 1_000;
    let v2 = PublishedManifest::publish(
        2,
        Anchors {
            current: vec![root_b.as_manifest_issuer()],
            retiring: vec![root_a.as_retiring_issuer(overlap_until)],
            revoked: vec![],
        },
        now,
        org_key,
    );
    v2.assert_accepts(&cred_a, now, "A still accepted during overlap");
    v2.assert_accepts(&cred_b, now, "B accepted during overlap");
    // Past the overlap deadline: A no longer a trusted anchor, B still is. Short-TTL
    // delegated credentials are re-minted continuously, so mint FRESH ones at `past` —
    // the question under test is the ROOT's trust, not the credential's freshness.
    let past = overlap_until + 1;
    let cred_a_past = root_a.issue_credential(&d1, 2, past);
    let cred_b_past = root_b.issue_credential(&d2, 2, past);
    v2.assert_refuses_untrusted_issuer(
        &cred_a_past,
        past,
        "A rejected after the overlap window closes",
    );
    v2.assert_accepts(&cred_b_past, past, "B accepted after cutover");

    // Phase 3 — manifest v3: Root A REVOKED (compromise). It stays LISTED (so its
    // material still resolves and the rejection reason is the decisive `Revoked`, not a
    // vague `Untrusted`) but is named in revoked_issuers; Root B stays current. This is
    // the compromise-response posture — one decisive action invalidates all of A's
    // descendants; a later manifest can drop A's entry entirely once it has propagated.
    let v3 = PublishedManifest::publish(
        3,
        Anchors {
            current: vec![root_a.as_manifest_issuer(), root_b.as_manifest_issuer()],
            retiring: vec![],
            revoked: vec![root_a.issuer_kid.clone()],
        },
        now,
        org_key,
    );
    v3.assert_refuses_untrusted_issuer(
        &cred_a,
        now,
        "revoking Root A invalidates its credential immediately, before exp",
    );
    v3.assert_accepts(&cred_b, now, "B unaffected by A's revocation");

    // Rollback protection: after accepting v3, a replayed v2 (which un-revokes A) is refused.
    assert_eq!(
        v2.load_at_floor(v3.version, now).map(|_| ()).unwrap_err(),
        TrustManifestError::Stale {
            version: 2,
            min_version: 3
        },
        "a rollback to the pre-revocation manifest is refused"
    );
}
