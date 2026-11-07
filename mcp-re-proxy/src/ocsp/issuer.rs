//! The issuer binding: whether a certificate was signed by the issuer it is checked against.
//!
//! `check` takes the issuer as an argument, so the CertID, the signer candidate and the
//! responder identity are all measured against it. Refusing an issuer that did not sign the
//! leaf keeps those checks on the key that issued the handshake-verified leaf and not on
//! whatever a peer presented after it.

use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use super::OcspError;

/// Whether `issuer_der` issued `leaf_der`: the leaf names it as issuer AND its signature
/// verifies under the issuer's key. A parse failure is `BadCertificate`.
pub(super) fn leaf_is_issued_by(leaf_der: &[u8], issuer_der: &[u8]) -> Result<bool, OcspError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| OcspError::BadCertificate(format!("leaf: {e}")))?;
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::BadCertificate(format!("issuer: {e}")))?;
    Ok(leaf.issuer() == issuer.subject() && cert_is_signed_by(&leaf, &issuer))
}

/// Whether `child`'s signature verifies under `issuer`'s public key, via
/// `x509-parser`'s `ring`-backed verifier. Always compiled with the `online_ocsp`
/// module (the workspace enables `x509-parser/verify` unconditionally), so the
/// shipping `online_ocsp` build performs the real cryptographic check.
pub(super) fn cert_is_signed_by(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    child.verify_signature(Some(issuer.public_key())).is_ok()
}

#[cfg(test)]
pub(super) mod tests {
    use super::leaf_is_issued_by;
    use crate::ocsp::request::tests::build_aia_extension_der;
    use crate::ocsp::signer::tests::mint_issuer;

    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::KeyPair;

    /// Mint a CA issuer (`IsCa::Ca` + `KeyCertSign`) able to SIGN child certs, and
    /// return both the rcgen `Issuer` (for signing) and the CA cert's DER.
    pub(in crate::ocsp) fn mint_ca_issuer() -> (rcgen::Issuer<'static, KeyPair>, Vec<u8>) {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-test-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).expect("ca self-signed");
        let der = cert.der().as_ref().to_vec();
        (rcgen::Issuer::new(params, key), der)
    }

    /// A leaf (carrying an AIA OCSP URL) SIGNED THROUGH `issuer`.
    pub(in crate::ocsp) fn mint_leaf_signed_by(issuer: &rcgen::Issuer<'_, KeyPair>) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                build_aia_extension_der("http://ocsp.example.test/r"),
            ));
        params
            .signed_by(&key, issuer)
            .expect("leaf signed by issuer")
            .der()
            .as_ref()
            .to_vec()
    }

    /// The relation between a leaf and its issuer: a leaf signed through a CA is issued by
    /// that CA and by no other.
    #[test]
    fn a_leaf_is_issued_by_the_ca_that_signed_it_and_by_no_other() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let (unrelated_issuer, _) = mint_issuer();
        let issued = mint_leaf_signed_by(&issuer);
        assert!(leaf_is_issued_by(&issued, &issuer_der).expect("parses"));
        assert!(!leaf_is_issued_by(&issued, &unrelated_issuer).expect("parses"));
    }
}
