// SPDX-License-Identifier: Apache-2.0
//! Root-signed compact JWS statements (RFC 7515 / RFC 7519), as every kind this profile
//! verifies shares them: the admission assertion, the authorization decision, the
//! authoritative admission record and the delegation credential.
//!
//! One codec and one window rule, because four readers of one security-relevant encoding
//! are four things that can disagree about what a well-formed, root-signed, currently valid
//! statement is. What a kind of statement MEANS stays with that kind: its media type, its
//! scope and currency checks, and the refusal vocabulary it maps each defect onto.

mod claim_window;
mod compact_jws;
mod protected_header;

pub(crate) use claim_window::ClaimWindow;
pub(crate) use claim_window::WindowDefect;
pub(crate) use compact_jws::CompactJws;
pub(crate) use compact_jws::IssueDefect;
pub(crate) use compact_jws::JwsDefect;
pub(crate) use compact_jws::RootVerified;
pub use protected_header::ProtectedHeader;
pub use protected_header::ALG_EDDSA;

/// What a claim set must state for the codec to verify its root signature and for a
/// reader to judge its currency.
pub(crate) trait RootSignedClaims {
    /// The root key id the claims name as their issuer; must equal the header `kid`.
    fn issuer_kid(&self) -> &str;
    /// The temporal claims.
    fn window(&self) -> ClaimWindow;
}

#[cfg(test)]
mod tests {
    use crate::admission::authenticate_admission;
    use crate::admission::issue_admission_assertion;
    use crate::admission::AdmissionBinding;
    use crate::admission::AdmissionClaims;
    use crate::admission::AdmissionStatus;
    use crate::admission_policy::AdmissionPolicy;
    use crate::authoritative_admission::record::issue_admission_state_record;
    use crate::authoritative_admission::record::verify_admission_state_record;
    use crate::authoritative_admission::record::AdmissionStateClaims;
    use crate::authoritative_admission::record::AdmissionStateCurrentness;
    use crate::delegation::issue_delegation_credential;
    use crate::delegation::verify_delegation_credential;
    use crate::delegation::Audience;
    use crate::delegation::Cnf;
    use crate::delegation::DelegatedJwk;
    use crate::delegation::DelegationClaims;
    use crate::delegation::DelegationHeader;
    use crate::delegation::DelegationVerifyParams;
    use crate::delegation::DELEGATION_ALG;
    use crate::delegation::DELEGATION_TYP;
    use crate::delegation::JWK_CRV_ED25519;
    use crate::delegation::JWK_KTY_OKP;
    use crate::delegation::KEY_USE_RESPONSE_SIGNING;
    use crate::error::HttpProfileError;
    use crate::pdp_decision::issue_authorization_decision;
    use crate::pdp_decision::verify_authorization_decision;
    use crate::pdp_decision::DecidedActor;
    use crate::pdp_decision::PdpDecisionClaims;
    use crate::pdp_decision::PdpDecisionFreshness;
    use crate::pdp_decision::PdpDecisionOutcome;
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey;
    use mcp_re_core::VerificationKey;

    const PROFILE: &str = "mcp-re-http-v1";
    const AUD: &str = "verifier-1";
    const KID: &str = "root-1";
    const NOW: i64 = 1_700_000_000;
    const SKEW: i64 = 30;

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[5u8; 32])
    }

    fn resolver() -> impl Fn(&str) -> Option<VerificationKey> {
        |kid: &str| (kid == KID).then(|| root().public_key())
    }

    fn sign(input: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
        b64url_decode(&root().sign(input))
            .map_err(|_| HttpProfileError::MalformedEvidence("test signature"))
    }

    struct Window {
        nbf: i64,
        iat: i64,
        exp: i64,
    }

    fn admission_accepts(w: &Window, now: i64, skew: i64) -> bool {
        let c = AdmissionClaims {
            iss: "a".into(),
            iat: w.iat,
            nbf: w.nbf,
            exp: w.exp,
            jti: "j".into(),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE.into(),
            mcp_re_admission_id: "w".into(),
            mcp_re_admitted_actor: "actor".into(),
            mcp_re_admission_generation: 1,
            mcp_re_admitted_state_digest: "d".into(),
            mcp_re_admission_status: AdmissionStatus::Admitted,
            issuer_kid: KID.into(),
        };
        let jws = issue_admission_assertion(&c, sign).expect("issued");
        let policy = AdmissionPolicy {
            max_assertion_age: 100_000,
            max_clock_skew: skew,
            ..AdmissionPolicy::default()
        };
        authenticate_admission(
            &AdmissionBinding::opaque_from(&c),
            &jws,
            "actor",
            PROFILE,
            &[AUD],
            &policy,
            now,
            resolver(),
        )
        .is_ok()
    }

    fn decision_accepts(w: &Window, now: i64, skew: i64) -> bool {
        let c = PdpDecisionClaims {
            iss: "p".into(),
            iat: w.iat,
            nbf: w.nbf,
            exp: w.exp,
            jti: "j".into(),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE.into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: "example.com".into(),
                subject: "s".into(),
            },
            mcp_re_decided_operation: "tools/call".into(),
            mcp_re_decided_target: None,
            mcp_re_decision: PdpDecisionOutcome::Permit,
            mcp_re_policy_version: "v".into(),
            issuer_kid: KID.into(),
        };
        let jws = issue_authorization_decision(&c, sign).expect("issued");
        let freshness = PdpDecisionFreshness {
            max_clock_skew: skew,
            max_decision_age: 100_000,
        };
        verify_authorization_decision(&jws, PROFILE, &[AUD], &freshness, now, resolver()).is_ok()
    }

    fn record_accepts(w: &Window, now: i64, skew: i64) -> bool {
        let c = AdmissionStateClaims {
            iss: "a".into(),
            iat: w.iat,
            nbf: w.nbf,
            exp: w.exp,
            mcp_re_profile: PROFILE.into(),
            mcp_re_admission_id: "w".into(),
            mcp_re_admission_generation: 1,
            mcp_re_admission_status: AdmissionStatus::Admitted,
            mcp_re_state_revision: 1,
            issuer_kid: KID.into(),
        };
        let jws = issue_admission_state_record(&c, sign).expect("issued");
        let currentness = AdmissionStateCurrentness {
            max_record_age: 100_000,
            max_clock_skew: skew,
        };
        verify_admission_state_record(&jws, "w", PROFILE, &currentness, None, now, resolver())
            .is_ok()
    }

    fn delegation_accepts(w: &Window, now: i64, skew: i64) -> bool {
        let delegated = SigningKey::from_seed_bytes(&[6u8; 32]).public_key();
        let header = DelegationHeader {
            typ: DELEGATION_TYP.into(),
            alg: DELEGATION_ALG.into(),
            kid: KID.into(),
        };
        let c = DelegationClaims {
            iss: "i".into(),
            iat: w.iat,
            nbf: w.nbf,
            exp: w.exp,
            jti: "j".into(),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE.into(),
            mcp_re_audience_hash: "h".into(),
            mcp_re_server_signer: "s".into(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            delegated_kid: "d".into(),
            issuer_kid: KID.into(),
            trust_epoch: "e".into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: "d".into(),
                    x: delegated.to_b64url(),
                },
            },
        };
        let jws = issue_delegation_credential(&root(), &header, &c);
        let params = DelegationVerifyParams {
            now,
            max_clock_skew: skew,
            verifier_audiences: &[AUD],
            expected_profile: PROFILE,
            expected_audience_hash: "h",
            expected_server_signer: "s",
            accepted_epochs: &["e"],
        };
        verify_delegation_credential(&jws, &params, resolver(), |_| false).is_ok()
    }

    /// One verdict from all four verifiers, in the order admission, decision, record,
    /// delegation.
    fn verdicts(w: &Window, now: i64, skew: i64) -> [bool; 4] {
        [
            admission_accepts(w, now, skew),
            decision_accepts(w, now, skew),
            record_accepts(w, now, skew),
            delegation_accepts(w, now, skew),
        ]
    }

    /// The same `(nbf, iat, exp, now, skew)` gets the same verdict from every verifier, and
    /// that verdict is the one [`ClaimWindow`](super::ClaimWindow) states.
    #[test]
    fn the_four_verifiers_share_one_window_rule() {
        let inside = Window {
            nbf: NOW - 10,
            iat: NOW - 10,
            exp: NOW + 300,
        };
        assert_eq!(verdicts(&inside, NOW, SKEW), [true; 4], "inside the window");

        let at_exp_plus_skew = Window {
            nbf: NOW - 400,
            iat: NOW - 400,
            exp: NOW - SKEW,
        };
        assert_eq!(
            verdicts(&at_exp_plus_skew, NOW, SKEW),
            [false; 4],
            "now == exp + skew is the first stale instant"
        );
        let last_fresh = Window {
            exp: NOW - SKEW + 1,
            ..at_exp_plus_skew
        };
        assert_eq!(
            verdicts(&last_fresh, NOW, SKEW),
            [true; 4],
            "now == exp + skew - 1 is the last fresh instant"
        );

        let degenerate = Window {
            nbf: NOW,
            iat: NOW,
            exp: NOW,
        };
        assert_eq!(
            verdicts(&degenerate, NOW, SKEW),
            [false; 4],
            "a degenerate window is refused"
        );

        let issued_ahead = Window {
            nbf: NOW - 10,
            iat: NOW + 3_600,
            exp: NOW + 7_200,
        };
        assert_eq!(
            verdicts(&issued_ahead, NOW, SKEW),
            [false; 4],
            "an issuance dated ahead of the verifier is refused"
        );
    }
}
