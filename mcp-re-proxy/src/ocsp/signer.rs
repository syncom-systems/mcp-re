//! Who signed an OCSP answer: the responder signature over `tbs_response_data` and the
//! `ResponderID` match against the key that verified it.
//!
//! Both are yes/no questions about certificates and signatures from bytes already in hand;
//! neither performs I/O or reads the clock (`now` is a parameter).

use std::time::SystemTime;

use der::Decode;
use der::Encode;
use x509_cert::Certificate;
use x509_ocsp::BasicOcspResponse;
use x509_ocsp::ResponderId;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use super::delegated_responder::delegated_responder_is_valid;
use super::sha1::sha1_hash;
use super::OcspError;

/// Verify the `BasicOcspResponse` signature over its `tbs_response_data` and
/// return the certificate whose public key verified it. The signer is EITHER the
/// issuer (direct) OR a delegated responder cert carried in `basic.certs` that is
/// itself signed by the issuer and carries the `id-kp-OCSPSigning` EKU. Fails
/// closed (`SignatureNotVerified`) when no candidate verifies.
///
/// The signer cert is returned as its DER bytes so the caller can run the
/// responder-identity check against the SAME key/name that verified the
/// signature.
///
/// The cryptographic verify (`x509-parser/verify`, enabled unconditionally at the
/// workspace level) is compiled into the `online_ocsp` module itself, so the
/// shipping `online_ocsp` + `--client-ocsp require` build performs this check for
/// real. When no candidate key verifies, this returns `SignatureNotVerified`, so a
/// `Good` status can NEVER be admitted on an unverified signature.
pub(super) fn verify_responder_signature(
    basic: &BasicOcspResponse,
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, OcspError> {
    let signature = ResponseSignature::of(basic)?;

    // Candidate 1: the issuer signed directly.
    if signature.verifies_under(issuer_der)? {
        return Ok(issuer_der.to_vec());
    }

    // Candidate 2..n: a delegated responder cert in `basic.certs` that is itself
    // issuer-signed AND carries the id-kp-OCSPSigning EKU.
    for cert in basic.certs.iter().flatten() {
        let cert_der = cert
            .to_der()
            .map_err(|e| OcspError::SignatureNotVerified(format!("responder cert DER: {e}")))?;
        if delegated_responder_is_valid(&cert_der, issuer_der, now)?
            && signature.verifies_under(&cert_der)?
        {
            return Ok(cert_der);
        }
    }

    Err(OcspError::SignatureNotVerified(
        "no issuer or delegated id-kp-OCSPSigning responder key verified the signature".into(),
    ))
}

/// What a responder signed and how: the DER of `tbs_response_data` (the exact bytes the
/// responder signed), the DER of the signature algorithm, and the signature value.
struct ResponseSignature<'a> {
    tbs_der: Vec<u8>,
    alg_der: Vec<u8>,
    /// The signature BIT STRING value (no unused-bits prefix); signatures are whole
    /// octets, so `unused_bits == 0`.
    value: &'a [u8],
}

impl<'a> ResponseSignature<'a> {
    /// The signature facts of `basic`, re-encoded to the bytes that were signed.
    fn of(basic: &'a BasicOcspResponse) -> Result<Self, OcspError> {
        let tbs_der = basic
            .tbs_response_data
            .to_der()
            .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode tbs: {e}")))?;
        let alg_der = basic
            .signature_algorithm
            .to_der()
            .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode sigalg: {e}")))?;
        Ok(ResponseSignature {
            tbs_der,
            alg_der,
            value: basic.signature.raw_bytes(),
        })
    }

    /// Whether the signature verifies under the public key of the certificate
    /// `signer_cert_der`. Algorithm-agnostic: RSA PKCS#1 v1.5 SHA-256/384/512 and ECDSA
    /// P-256/P-384, via `x509-parser`'s `ring`-backed `verify_signature`.
    ///
    /// Always compiled with the `online_ocsp` module (the workspace enables
    /// `x509-parser/verify` unconditionally), so the shipping `online_ocsp` +
    /// `--client-ocsp require` build performs the REAL RFC 6960 §3.2 signature
    /// check. A non-verifying response yields `Ok(false)`, so the caller fails closed
    /// (status → Unknown → deny): no `Good` is ever admitted on an unverified
    /// signature.
    fn verifies_under(&self, signer_cert_der: &[u8]) -> Result<bool, OcspError> {
        let (_, signer) = X509Certificate::from_der(signer_cert_der)
            .map_err(|e| OcspError::SignatureNotVerified(format!("signer cert parse: {e}")))?;
        let (_, sig_alg) = x509_parser::x509::AlgorithmIdentifier::from_der(&self.alg_der)
            .map_err(|e| {
                OcspError::SignatureNotVerified(format!("signature algorithm parse: {e}"))
            })?;
        // The signature value as an asn1-rs BIT STRING (whole octets → 0 unused bits).
        let sig_bits = asn1_rs::BitString::new(0, self.value);
        Ok(x509_parser::verify::verify_signature(
            signer.public_key(),
            &sig_alg,
            &sig_bits,
            &self.tbs_der,
        )
        .is_ok())
    }
}

/// Whether the response's `responder_id` identifies `signer_cert_der` — the cert
/// whose key verified the signature. `byName` must equal the signer's subject DN;
/// `byKey` must equal the SHA-1 hash of the signer's `subjectPublicKey` bits
/// (RFC 6960 §4.2.1 KeyHash). Pure.
pub(super) fn responder_id_matches(responder_id: &ResponderId, signer_cert_der: &[u8]) -> bool {
    let Ok(signer) = Certificate::from_der(signer_cert_der) else {
        return false;
    };
    match responder_id {
        ResponderId::ByName(name) => {
            let (Ok(a), Ok(b)) = (name.to_der(), signer.tbs_certificate.subject.to_der()) else {
                return false;
            };
            a == b
        }
        ResponderId::ByKey(key_hash) => {
            // KeyHash is the SHA-1 hash of the responder public-key BIT STRING
            // value. Compute it from the signer's SPKI subjectPublicKey bits.
            let spk_bits = signer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let digest = sha1_hash(spk_bits);
            key_hash.as_bytes() == digest.as_slice()
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::responder_id_matches;

    use der::Decode;
    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use x509_cert::Certificate;
    use x509_ocsp::ResponderId;

    /// Mint a self-signed CA-ish issuer certificate (its key/subject feed the
    /// CertID hash) and return `(issuer_der, issuer_key)`.
    pub(in crate::ocsp) fn mint_issuer() -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().expect("issuer key");
        let mut params = CertificateParams::new(Vec::new()).expect("issuer params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-test-ca");
        let cert = params.self_signed(&key).expect("issuer self-signed");
        (cert.der().as_ref().to_vec(), key)
    }

    #[test]
    fn responder_id_byname_matches_issuer() {
        let (issuer_der, _) = mint_issuer();
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let by_name = ResponderId::ByName(issuer.tbs_certificate.subject.clone());
        assert!(responder_id_matches(&by_name, &issuer_der));
        // A cert with a DIFFERENT subject DN must not match.
        let other_key = KeyPair::generate().expect("other key");
        let mut other_params = CertificateParams::new(Vec::new()).expect("other params");
        other_params
            .distinguished_name
            .push(DnType::CommonName, "some-other-ca");
        let other = other_params
            .self_signed(&other_key)
            .expect("other self-signed");
        assert!(!responder_id_matches(&by_name, other.der().as_ref()));
    }
}
