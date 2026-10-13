// SPDX-License-Identifier: Apache-2.0
//! Reading a compact delegation credential as its own statement of itself, with nothing
//! judged about whether that statement may be believed.
//!
//! Both sides of this crate read these bytes: the verifier deciding whether a presented
//! credential may be believed, and the custody machine deriving the window it will serve
//! under from the credential it is about to publish. Both read through the one codec.

use super::jose::CompactJws;
use super::DelegationClaims;
use super::DelegationHeader;
use crate::error::HttpProfileError;

/// The header and claims a compact delegation credential states, with no judgement passed
/// on whether they may be believed.
///
/// `pub(crate)` for the issuance side: [`custody::ActiveDelegatedKey`](crate::custody)
/// derives its window from the exact credential it is about to publish, and needs the
/// credential's own statement of itself to do so. Deciding whether a credential is
/// ACCEPTABLE is [`verify_delegation_credential`](super::verify_delegation_credential)'s,
/// a different authority.
pub(crate) fn parse_credential(
    compact_jws: &str,
) -> Result<(DelegationHeader, DelegationClaims), HttpProfileError> {
    let jws = CompactJws::split(compact_jws).map_err(invalid)?;
    Ok((
        jws.header().map_err(invalid)?,
        jws.claims().map_err(invalid)?,
    ))
}

/// Every way a credential fails to read is one refusal on the wire.
fn invalid(_: super::jose::JwsDefect) -> HttpProfileError {
    HttpProfileError::DelegationCredentialInvalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::issue_delegation_credential;
    use crate::delegation::tests::good_claims;
    use crate::delegation::tests::good_header;
    use mcp_re_core::b64url_encode;
    use mcp_re_core::SigningKey;

    #[test]
    fn a_credential_reads_back_as_the_header_and_claims_it_was_issued_with() {
        let root = SigningKey::from_seed_bytes(&[1u8; 32]);
        let delegated = SigningKey::from_seed_bytes(&[2u8; 32]).public_key();
        let (header, claims) = (good_header(), good_claims(&delegated));
        let jws = issue_delegation_credential(&root, &header, &claims);
        assert_eq!(parse_credential(&jws).expect("parses"), (header, claims));
    }

    #[test]
    fn a_fourth_segment_or_a_non_credential_payload_is_refused() {
        let h = b64url_encode(br#"{"typ":"t","alg":"EdDSA","kid":"k"}"#);
        let p = b64url_encode(br#"{"b":2}"#);
        for jws in [
            format!("{h}.{p}.cc.dd"),
            format!("{h}.{p}.cc"),
            "!!.bb.cc".to_owned(),
        ] {
            assert!(
                matches!(
                    parse_credential(&jws),
                    Err(HttpProfileError::DelegationCredentialInvalid)
                ),
                "{jws}"
            );
        }
    }
}
