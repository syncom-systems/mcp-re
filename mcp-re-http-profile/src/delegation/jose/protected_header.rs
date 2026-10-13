// SPDX-License-Identifier: Apache-2.0
//! The protected header of a root-signed compact JWS, and the one algorithm it may name.

use serde::Deserialize;
use serde::Serialize;

/// The only JWS algorithm this profile signs or verifies: Ed25519 per RFC 8037. There is
/// no agility and no `none`; a header naming anything else is refused before its claims
/// are read.
pub const ALG_EDDSA: &str = "EdDSA";

/// The JWS protected header every root-signed statement in this profile carries.
///
/// `typ` is the statement's media type, pinned by each kind of statement so one kind can
/// never be presented as another; `alg` must equal [`ALG_EDDSA`]; `kid` names the issuing
/// root and is resolved through the trust seam, never trusted because it is named here,
/// and must equal the `issuer_kid` the claims name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedHeader {
    pub typ: String,
    pub alg: String,
    pub kid: String,
}

impl ProtectedHeader {
    /// The header an issuer signs under: `typ` as given, `alg` pinned, `kid` the issuing root.
    pub(crate) fn eddsa(typ: &str, kid: &str) -> Self {
        ProtectedHeader {
            typ: typ.to_owned(),
            alg: ALG_EDDSA.to_owned(),
            kid: kid.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issued_header_is_pinned_to_eddsa() {
        let h = ProtectedHeader::eddsa("x+jws", "root");
        assert_eq!(h.alg, ALG_EDDSA);
        assert_eq!(h.typ, "x+jws");
        assert_eq!(h.kid, "root");
    }

    #[test]
    fn an_unknown_header_member_does_not_parse() {
        let err = serde_json::from_str::<ProtectedHeader>(
            r#"{"typ":"t","alg":"EdDSA","kid":"k","crit":[]}"#,
        );
        assert!(err.is_err());
    }
}
