//! The OCSP `CertID` (RFC 6960 §4.1.1): built once for the request and recomputed for the
//! response, so the `SingleResponse` this module acts on is bound to the certificate that was
//! asked about and no other.
//!
//! SHA-256 only: the responder must answer SHA-256 CertIDs.

use der::asn1::Null;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::Decode;
use der::Encode;
use sha2::Digest;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_ocsp::BasicOcspResponse;
use x509_ocsp::CertId;
use x509_ocsp::SingleResponse;

use super::OcspError;

/// The `id-sha256` digest-algorithm OID (`2.16.840.1.101.3.4.2.1`). The CertID
/// hash algorithm is SHA-256, so the responder must be configured to answer
/// SHA-256 CertIDs. Declared as a literal so the build does not depend on a
/// digest crate exposing its `AssociatedOid` impl under the current feature set.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Build the SHA-256 `CertID` for `leaf_der` under `issuer_der`, decoding both
/// certificates. The same CertID is sent in the request AND recomputed after the
/// response arrives to bind the acted-on `SingleResponse` to our query.
pub(super) fn build_cert_id(leaf_der: &[u8], issuer_der: &[u8]) -> Result<CertId, OcspError> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| OcspError::BadCertificate(format!("leaf: {e}")))?;
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::BadCertificate(format!("issuer: {e}")))?;
    build_sha256_cert_id(&issuer, &leaf)
}

/// Build the SHA-256 `CertID` (RFC 6960 §4.1.1) for `cert` under `issuer`:
///
///   * `hashAlgorithm` = `id-sha256`;
///   * `issuerNameHash` = SHA-256 of the issuer's DER-encoded subject DN;
///   * `issuerKeyHash` = SHA-256 of the issuer's `subjectPublicKey` raw bits
///     (the BIT STRING value, excluding tag/length/unused-bits);
///   * `serialNumber` = the leaf's serial number.
///
/// Built by hand (rather than `CertId::from_cert::<Sha256>`) so the build does
/// not require `sha2::Sha256: AssociatedOid`, which is gated behind a `sha2`
/// crate feature not enabled in this build's dependency set.
fn build_sha256_cert_id(issuer: &Certificate, cert: &Certificate) -> Result<CertId, OcspError> {
    let issuer_subject_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("issuer subject DER: {e}")))?;
    let issuer_name_hash = Sha256::digest(&issuer_subject_der);
    let issuer_key_hash = Sha256::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer name hash: {e}")))?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer key hash: {e}")))?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    })
}

/// Select the `SingleResponse` whose `CertID` binds to `expected` — the cert we
/// asked about. Compares the binding fields (hash-algorithm OID, issuer name
/// hash, issuer key hash, serial number) so a response answering a DIFFERENT cert
/// is never mistaken for evidence about ours. Returns `None` when none matches, and when
/// MORE THAN ONE does: two verdicts for one certificate would resolve to whichever came
/// first, so the caller fails closed instead. Pure.
pub(super) fn select_matching_single_response<'a>(
    basic: &'a BasicOcspResponse,
    expected: &CertId,
) -> Option<&'a SingleResponse> {
    let mut matching = basic
        .tbs_response_data
        .responses
        .iter()
        .filter(|single| cert_ids_bind(&single.cert_id, expected));
    let only = matching.next()?;
    matching.next().is_none().then_some(only)
}

/// Whether two CertIDs identify the same certificate: same hash-algorithm OID and
/// identical issuer name hash, issuer key hash, and serial number.
fn cert_ids_bind(a: &CertId, b: &CertId) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number == b.serial_number
}

#[cfg(test)]
mod tests {
    use super::build_cert_id;
    use super::cert_ids_bind;
    use super::select_matching_single_response;
    use crate::ocsp::pipeline::tests::build_fixture;
    use crate::ocsp::pipeline::tests::ResponseFixture;
    use crate::ocsp::request::tests::mint_leaf_with_aia;
    use crate::ocsp::signer::tests::mint_issuer;

    #[test]
    fn certid_binding_matches_only_same_cert() {
        let (issuer_der, _) = mint_issuer();
        let leaf_a = mint_leaf_with_aia("http://a/r");
        let leaf_b = mint_leaf_with_aia("http://b/r");
        let id_a = build_cert_id(&leaf_a, &issuer_der).expect("id a");
        let id_a2 = build_cert_id(&leaf_a, &issuer_der).expect("id a2");
        let id_b = build_cert_id(&leaf_b, &issuer_der).expect("id b");
        assert!(cert_ids_bind(&id_a, &id_a2), "same cert binds");
        assert!(
            !cert_ids_bind(&id_a, &id_b),
            "different serial does not bind"
        );
    }

    #[test]
    fn select_matching_single_response_requires_binding() {
        let other_leaf = mint_leaf_with_aia("http://other/r");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = build_cert_id(&other_leaf, &issuer_der).expect("wrong id");
        let built = build_fixture(ResponseFixture {
            cert_id: Some(wrong_id.clone()),
            ..ResponseFixture::good()
        });
        let requested = build_cert_id(&built.leaf_der, &built.issuer_der).expect("requested id");
        assert!(!cert_ids_bind(&requested, &wrong_id));
        let basic = built.basic();
        assert!(
            select_matching_single_response(&basic, &requested).is_none(),
            "a SingleResponse for a different CertID must not be selected"
        );
    }
}
