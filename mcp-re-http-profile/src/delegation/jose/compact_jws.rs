// SPDX-License-Identifier: Apache-2.0
//! A compact JWS (RFC 7515 §7.1): the three segments, their decoding, the root signature
//! over the first two, and the inverse at issuance.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::protected_header::ProtectedHeader;
use super::protected_header::ALG_EDDSA;
use super::RootSignedClaims;
use crate::error::HttpProfileError;

/// Raw Ed25519 signature octets (RFC 8032). The external root-signer seam must return
/// exactly this many; a KMS handing back a DER-wrapped or truncated signature is a
/// contract violation caught at issuance rather than published as a statement no verifier
/// can read.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Why a presented compact JWS is not a root-signed statement of the kind the reader
/// expects. Each reader maps these onto its own refusal vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwsDefect {
    /// Not exactly three non-empty dot-separated segments.
    Shape,
    /// A header or payload segment is not base64url without padding.
    Base64Url,
    /// A decoded header or payload is not the JSON the reader expects.
    Json,
    /// The header's `typ` is not the one the reader pins, or its `alg` is not EdDSA.
    MediaType,
    /// The header `kid` is not the `issuer_kid` the claims name.
    KidDisagrees,
    /// The issuer kid resolves to no trusted root.
    IssuerUntrusted,
    /// The signature segment does not verify under the resolved root.
    SignatureInvalid,
}

/// Why a statement could not be issued.
#[derive(Debug)]
pub(crate) enum IssueDefect {
    /// The header or claims do not serialize.
    Unformable,
    /// The signer returned something other than 64 raw Ed25519 octets.
    SignatureLength,
    /// The signer seam itself refused.
    Signer(HttpProfileError),
}

/// Claims whose root signature verified, with the root that signed them.
pub(crate) struct RootVerified<C> {
    pub(crate) claims: C,
    pub(crate) root: VerificationKey,
}

/// The three segments of a compact JWS, split and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactJws<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

impl<'a> CompactJws<'a> {
    /// Exactly three non-empty segments, in order.
    pub(crate) fn split(jws: &'a str) -> Result<Self, JwsDefect> {
        let mut it = jws.split('.');
        match (it.next(), it.next(), it.next(), it.next()) {
            (Some(header), Some(payload), Some(signature), None)
                if !header.is_empty() && !payload.is_empty() && !signature.is_empty() =>
            {
                Ok(CompactJws {
                    header,
                    payload,
                    signature,
                })
            }
            _ => Err(JwsDefect::Shape),
        }
    }

    /// The protected header, decoded and nothing judged about it.
    pub(crate) fn header(&self) -> Result<ProtectedHeader, JwsDefect> {
        decode_json(self.header)
    }

    /// The payload as the reader's claim type, decoded and nothing judged about it.
    pub(crate) fn claims<C: DeserializeOwned>(&self) -> Result<C, JwsDefect> {
        decode_json(self.payload)
    }

    /// The claims, once a trusted root has signed them.
    ///
    /// In order: the header names `typ` and EdDSA; the header `kid` is the claims'
    /// `issuer_kid`; that kid resolves through `resolve_root` to a trusted key (a kid never
    /// introduces trust); and the signature verifies under that key over the first two
    /// segments. Nothing in the returned claims was read before the root signed it.
    pub(crate) fn verify_root<C: DeserializeOwned + RootSignedClaims>(
        &self,
        typ: &str,
        resolve_root: impl FnOnce(&str) -> Option<VerificationKey>,
    ) -> Result<RootVerified<C>, JwsDefect> {
        let header = self.header()?;
        if header.typ != typ || header.alg != ALG_EDDSA {
            return Err(JwsDefect::MediaType);
        }
        let claims: C = self.claims()?;
        if header.kid != claims.issuer_kid() {
            return Err(JwsDefect::KidDisagrees);
        }
        let root = resolve_root(claims.issuer_kid()).ok_or(JwsDefect::IssuerUntrusted)?;
        let signing_input = format!("{}.{}", self.header, self.payload);
        verify_ed25519_with(
            signing_input.as_bytes(),
            self.signature,
            &root,
            McpReError::InvalidSignature,
        )
        .map_err(|_| JwsDefect::SignatureInvalid)?;
        Ok(RootVerified { claims, root })
    }

    /// Issue a statement: `base64url(header) "." base64url(claims)` signed by `sign_root`,
    /// which receives exactly that ASCII signing input and must return the 64 raw Ed25519
    /// signature octets.
    pub(crate) fn issue<C: Serialize>(
        header: &ProtectedHeader,
        claims: &C,
        sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    ) -> Result<String, IssueDefect> {
        let unformable = |_| IssueDefect::Unformable;
        let h = b64url_encode(&serde_json::to_vec(header).map_err(unformable)?);
        let p = b64url_encode(&serde_json::to_vec(claims).map_err(unformable)?);
        let sig = sign_root(format!("{h}.{p}").as_bytes()).map_err(IssueDefect::Signer)?;
        if sig.len() != ED25519_SIGNATURE_LEN {
            return Err(IssueDefect::SignatureLength);
        }
        Ok(format!("{h}.{p}.{}", b64url_encode(&sig)))
    }
}

fn decode_json<T: DeserializeOwned>(segment: &str) -> Result<T, JwsDefect> {
    let bytes = b64url_decode(segment).map_err(|_| JwsDefect::Base64Url)?;
    serde_json::from_slice(&bytes).map_err(|_| JwsDefect::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use serde::Deserialize;

    const TYP: &str = "test+jws";
    const KID: &str = "root-kid";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Claims {
        issuer_kid: String,
        n: u8,
    }

    impl RootSignedClaims for Claims {
        fn issuer_kid(&self) -> &str {
            &self.issuer_kid
        }
        fn window(&self) -> super::super::ClaimWindow {
            super::super::ClaimWindow {
                iat: 0,
                nbf: 0,
                exp: 1,
            }
        }
    }

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[3u8; 32])
    }

    fn signer(key: &SigningKey) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError> + '_ {
        move |input: &[u8]| {
            b64url_decode(&key.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
        }
    }

    fn claims() -> Claims {
        Claims {
            issuer_kid: KID.into(),
            n: 7,
        }
    }

    fn issued(header: &ProtectedHeader, key: &SigningKey) -> String {
        CompactJws::issue(header, &claims(), signer(key)).expect("issued")
    }

    fn trusting(key: &SigningKey) -> impl Fn(&str) -> Option<VerificationKey> {
        let public = key.public_key();
        move |kid: &str| (kid == KID).then(|| public.clone())
    }

    fn verify(jws: &str) -> Result<Claims, JwsDefect> {
        CompactJws::split(jws)?
            .verify_root::<Claims>(TYP, trusting(&root()))
            .map(|v| v.claims)
    }

    #[test]
    fn a_genuine_statement_round_trips_with_its_root() {
        let jws = issued(&ProtectedHeader::eddsa(TYP, KID), &root());
        let verified = CompactJws::split(&jws)
            .expect("split")
            .verify_root::<Claims>(TYP, trusting(&root()))
            .expect("verifies");
        assert_eq!(verified.claims, claims());
        assert_eq!(verified.root.to_b64url(), root().public_key().to_b64url());
    }

    #[test]
    fn three_non_empty_segments_split_in_order() {
        assert_eq!(
            CompactJws::split("aa.bb.cc"),
            Ok(CompactJws {
                header: "aa",
                payload: "bb",
                signature: "cc"
            })
        );
        for bad in ["", "aa.bb", "aa.bb.cc.dd", "aa..cc", ".bb.cc", "aa.bb."] {
            assert_eq!(CompactJws::split(bad), Err(JwsDefect::Shape), "{bad:?}");
        }
    }

    #[test]
    fn segment_encoding_and_json_are_refused_separately() {
        let jws = issued(&ProtectedHeader::eddsa(TYP, KID), &root());
        let parts = CompactJws::split(&jws).expect("split");
        let not_json = b64url_encode(b"not json");
        assert_eq!(
            verify(&format!("!!!.{}.{}", parts.payload, parts.signature)),
            Err(JwsDefect::Base64Url)
        );
        assert_eq!(
            verify(&format!("{not_json}.{}.{}", parts.payload, parts.signature)),
            Err(JwsDefect::Json)
        );
        assert_eq!(
            verify(&format!("{}.{not_json}.{}", parts.header, parts.signature)),
            Err(JwsDefect::Json)
        );
    }

    #[test]
    fn another_media_type_or_algorithm_is_refused_before_the_claims_are_read() {
        let other_typ = ProtectedHeader::eddsa("other+jws", KID);
        assert_eq!(
            verify(&issued(&other_typ, &root())),
            Err(JwsDefect::MediaType)
        );
        let mut none = ProtectedHeader::eddsa(TYP, KID);
        none.alg = "none".into();
        assert_eq!(verify(&issued(&none, &root())), Err(JwsDefect::MediaType));
    }

    #[test]
    fn a_header_kid_disagreeing_with_the_claims_is_refused() {
        let jws = issued(&ProtectedHeader::eddsa(TYP, "another-root"), &root());
        assert_eq!(verify(&jws), Err(JwsDefect::KidDisagrees));
    }

    #[test]
    fn an_unresolvable_issuer_is_untrusted_not_a_bad_signature() {
        let jws = issued(&ProtectedHeader::eddsa(TYP, KID), &root());
        let unresolved = CompactJws::split(&jws)
            .expect("split")
            .verify_root::<Claims>(TYP, |_| None);
        assert!(matches!(unresolved, Err(JwsDefect::IssuerUntrusted)));
    }

    #[test]
    fn a_signature_by_another_key_or_a_tampered_one_is_invalid() {
        let impostor = SigningKey::from_seed_bytes(&[4u8; 32]);
        assert_eq!(
            verify(&issued(&ProtectedHeader::eddsa(TYP, KID), &impostor)),
            Err(JwsDefect::SignatureInvalid)
        );
        let jws = issued(&ProtectedHeader::eddsa(TYP, KID), &root());
        let parts = CompactJws::split(&jws).expect("split");
        let mut sig = b64url_decode(parts.signature).expect("signature bytes");
        sig[0] ^= 0x01;
        let forged = format!("{}.{}.{}", parts.header, parts.payload, b64url_encode(&sig));
        assert_eq!(verify(&forged), Err(JwsDefect::SignatureInvalid));
        assert_eq!(
            verify(&format!("{}.{}.!!!", parts.header, parts.payload)),
            Err(JwsDefect::SignatureInvalid)
        );
    }

    #[test]
    fn a_signer_returning_other_than_64_octets_is_refused_at_issuance() {
        let header = ProtectedHeader::eddsa(TYP, KID);
        for wrong in [0usize, 63, 65, 71] {
            assert!(
                matches!(
                    CompactJws::issue(&header, &claims(), |_| Ok(vec![0u8; wrong])),
                    Err(IssueDefect::SignatureLength)
                ),
                "{wrong}"
            );
        }
        assert!(CompactJws::issue(&header, &claims(), |_| Ok(vec![0u8; 64])).is_ok());
    }

    #[test]
    fn a_signer_refusal_is_propagated() {
        let header = ProtectedHeader::eddsa(TYP, KID);
        assert!(matches!(
            CompactJws::issue(&header, &claims(), |_| Err(
                HttpProfileError::InvalidSignature
            )),
            Err(IssueDefect::Signer(HttpProfileError::InvalidSignature))
        ));
    }
}
