// SPDX-License-Identifier: Apache-2.0
//! Producing a decision. The authority side of the profile.

use super::claims::PdpDecisionClaims;
use super::claims::PDP_DECISION_TYP;
use crate::delegation::jose::CompactJws;
use crate::delegation::jose::IssueDefect;
use crate::delegation::jose::ProtectedHeader;
use crate::error::HttpProfileError;

/// Issue an authorization decision as a compact JWS. The private-key operation is delegated,
/// exactly as the admission authority's is.
pub fn issue_authorization_decision(
    claims: &PdpDecisionClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    let header = ProtectedHeader::eddsa(PDP_DECISION_TYP, &claims.issuer_kid);
    CompactJws::issue(&header, claims, sign_root).map_err(|defect| match defect {
        IssueDefect::Unformable => HttpProfileError::MalformedEvidence("decision"),
        IssueDefect::SignatureLength => {
            HttpProfileError::MalformedEvidence("decision signature length")
        }
        IssueDefect::Signer(e) => e,
    })
}

#[cfg(test)]
mod tests {
    use super::issue_authorization_decision;
    use crate::delegation::Audience;
    use crate::error::HttpProfileError;
    use crate::pdp_decision::claims::DecidedActor;
    use crate::pdp_decision::claims::PdpDecisionClaims;
    use crate::pdp_decision::claims::PdpDecisionHeader;
    use crate::pdp_decision::claims::PdpDecisionOutcome;
    use crate::pdp_decision::claims::PDP_DECISION_ALG;
    use crate::pdp_decision::claims::PDP_DECISION_TYP;
    use mcp_re_core::b64url_decode;

    fn claims() -> PdpDecisionClaims {
        PdpDecisionClaims {
            iss: "did:example:pdp".into(),
            iat: 1,
            nbf: 1,
            exp: 2,
            jti: "d1".into(),
            aud: Audience::One("verifier-1".into()),
            mcp_re_profile: "mcp-re-http-v1".into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: "example.com".into(),
                subject: "did:example:a".into(),
            },
            mcp_re_decided_operation: "tools/list".into(),
            mcp_re_decided_target: None,
            mcp_re_decision: PdpDecisionOutcome::Permit,
            mcp_re_policy_version: "v1".into(),
            issuer_kid: "pdp-root-1".into(),
        }
    }

    #[test]
    fn the_header_is_minted_here_and_names_this_profile() {
        // The issuer does not choose `typ`/`alg`, and the header `kid` is taken from the
        // claims rather than supplied beside them: two places to state one fact is how they
        // come to disagree.
        let jws = issue_authorization_decision(&claims(), |_| Ok(vec![0u8; 64])).expect("issues");
        let h: PdpDecisionHeader =
            serde_json::from_slice(&b64url_decode(jws.split('.').next().unwrap()).unwrap())
                .expect("header");
        assert_eq!(h.typ, PDP_DECISION_TYP);
        assert_eq!(h.alg, PDP_DECISION_ALG);
        assert_eq!(h.kid, claims().issuer_kid);
    }

    #[test]
    fn the_signature_covers_the_header_and_the_claims() {
        let mut seen = Vec::new();
        let jws = issue_authorization_decision(&claims(), |i| {
            seen = i.to_vec();
            Ok(vec![0u8; 64])
        })
        .expect("issues");
        let (h, rest) = jws.split_once('.').expect("compact");
        let (p, _) = rest.split_once('.').expect("compact");
        assert_eq!(seen, format!("{h}.{p}").into_bytes());
    }

    #[test]
    fn a_signer_that_refuses_does_not_yield_a_decision() {
        assert!(issue_authorization_decision(&claims(), |_| Err(
            HttpProfileError::MalformedEvidence("no key")
        ))
        .is_err());
    }
}
