//! The OCSP request this module sends and the facts about it the response is checked against.
//!
//! [`SentRequest`] is the one value that holds a request's DER, its CertID, its nonce and the
//! issuer it was built against, so the response checks measure the answer against exactly
//! what was asked and no caller can pair a CertID from one query with the nonce of another.

use der::Encode;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::ext::Nonce;
use x509_ocsp::CertId;
use x509_ocsp::Request;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::AuthorityInfoAccess;
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

use super::cert_id::build_cert_id;
use super::OcspError;

/// The OCSP access-method OID `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`) used inside the
/// Authority Information Access (AIA) extension to point at the responder URL.
const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// The request nonce length in bytes (RFC 8954 permits 1..32; 16 is ample
/// entropy against replay/substitution while staying within responders that cap
/// nonce length). The nonce is freshly drawn per request from the OS CSPRNG.
const OCSP_NONCE_LEN: usize = 16;

/// A DER-encoded OCSP request together with what a response to it must match: the CertID it
/// asked about, the nonce it carried, and the issuer both were derived against.
pub(super) struct SentRequest {
    der: Vec<u8>,
    cert_id: CertId,
    nonce: Vec<u8>,
    issuer_der: Vec<u8>,
}

impl SentRequest {
    /// Build the request for `leaf_der` against `issuer_der`, carrying a SHA-256 CertID and
    /// a fresh nonce as the RFC 6960 §4.4.1 Nonce extension. The nonce binds the response to
    /// THIS request: a captured, replayed response carries a stale (mismatched) nonce and is
    /// rejected (RFC 6960 §4.4.1 / RFC 8954). Pure (no network).
    pub(super) fn new(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Self, OcspError> {
        Self::with_nonce(leaf_der, issuer_der, random_nonce()?)
    }

    /// As [`SentRequest::new`], carrying the given `nonce` instead of a drawn one.
    pub(super) fn with_nonce(
        leaf_der: &[u8],
        issuer_der: &[u8],
        nonce: Vec<u8>,
    ) -> Result<Self, OcspError> {
        let cert_id = build_cert_id(leaf_der, issuer_der)?;
        let der = request_der(cert_id.clone(), &nonce)?;
        Ok(SentRequest {
            der,
            cert_id,
            nonce,
            issuer_der: issuer_der.to_vec(),
        })
    }

    /// The DER bytes to POST to the responder.
    pub(super) fn der(&self) -> &[u8] {
        &self.der
    }

    /// The CertID the request asked about.
    pub(super) fn cert_id(&self) -> &CertId {
        &self.cert_id
    }

    /// The nonce the request carried.
    pub(super) fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The issuer the CertID, the signer candidate and the responder identity are measured
    /// against.
    pub(super) fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }
}

/// Draw a fresh `OCSP_NONCE_LEN`-byte nonce from the OS CSPRNG (`getrandom`).
/// Fails closed (the caller turns the error into a rejected connection) if the
/// platform RNG is unavailable rather than sending a predictable nonce.
fn random_nonce() -> Result<Vec<u8>, OcspError> {
    let mut bytes = vec![0u8; OCSP_NONCE_LEN];
    getrandom::fill(&mut bytes)
        .map_err(|e| OcspError::BuildRequest(format!("nonce CSPRNG: {e}")))?;
    Ok(bytes)
}

/// DER-encode an OCSP request for `cert_id` with `nonce` as its only extension.
fn request_der(cert_id: CertId, nonce: &[u8]) -> Result<Vec<u8>, OcspError> {
    let nonce_ext =
        Nonce::new(nonce.to_vec()).map_err(|e| OcspError::BuildRequest(format!("nonce: {e}")))?;
    let ocsp_request = OcspRequestBuilder::default()
        .with_request(Request::new(cert_id))
        .with_extension(nonce_ext)
        .map_err(|e| OcspError::BuildRequest(format!("nonce extension: {e}")))?
        .build();
    ocsp_request
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("DER encode: {e}")))
}

/// Extract the OCSP responder URL from a leaf certificate's Authority
/// Information Access (AIA) extension — the first `id-ad-ocsp` access
/// description whose location is a URI. Returns `None` if the cert cannot be
/// parsed, has no AIA extension, or has no OCSP URI entry. Pure (no network).
pub(super) fn extract_ocsp_responder_url(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityInfoAccess(aia) => ocsp_uri(aia),
            _ => None,
        })
}

/// The first `id-ad-ocsp` access description in `aia` whose location is a URI.
fn ocsp_uri(aia: &AuthorityInfoAccess<'_>) -> Option<String> {
    aia.iter().find_map(|desc| {
        let is_ocsp = desc.access_method.to_id_string() == ID_AD_OCSP;
        match &desc.access_location {
            GeneralName::URI(uri) if is_ocsp => Some((*uri).to_string()),
            _ => None,
        }
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::extract_ocsp_responder_url;
    use super::SentRequest;
    use crate::ocsp::signer::tests::mint_issuer;
    use der::Decode;
    use der::Encode;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use x509_ocsp::builder::OcspRequestBuilder;
    use x509_ocsp::OcspRequest;

    /// Mint a leaf certificate carrying an AIA OCSP responder URL via a custom
    /// extension (rcgen 0.14 supports raw custom extensions). The AIA value is a
    /// hand-built `AuthorityInfoAccessSyntax` with one `id-ad-ocsp` access
    /// description pointing at `ocsp_url`.
    pub(in crate::ocsp) fn mint_leaf_with_aia(ocsp_url: &str) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example");
        // AIA OID 1.3.6.1.5.5.7.1.1; value = SEQUENCE OF AccessDescription, each
        // SEQUENCE { accessMethod OID, accessLocation [6] IA5String(url) }.
        let aia_der = build_aia_extension_der(ocsp_url);
        let ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], aia_der);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    /// Hand-encode an `AuthorityInfoAccessSyntax` containing a single
    /// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) access description whose location is the
    /// context-tag-6 IA5String form of `url`. Minimal DER, sufficient for
    /// x509-parser to recover the URL.
    pub(in crate::ocsp) fn build_aia_extension_der(url: &str) -> Vec<u8> {
        // accessMethod: OID 1.3.6.1.5.5.7.48.1 → DER bytes.
        let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        // accessLocation: [6] IA5String (context-specific primitive tag 6).
        let url_bytes = url.as_bytes();
        let mut location = vec![0x86u8, url_bytes.len() as u8];
        location.extend_from_slice(url_bytes);
        // AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
        let mut access_desc_body = Vec::new();
        access_desc_body.extend_from_slice(&oid);
        access_desc_body.extend_from_slice(&location);
        let mut access_desc = vec![0x30u8, access_desc_body.len() as u8];
        access_desc.extend_from_slice(&access_desc_body);
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        let mut aia = vec![0x30u8, access_desc.len() as u8];
        aia.extend_from_slice(&access_desc);
        aia
    }

    #[test]
    fn aia_url_extraction_reads_ocsp_responder() {
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/responder");
        let url = extract_ocsp_responder_url(&leaf);
        assert_eq!(
            url.as_deref(),
            Some("http://ocsp.example.test/responder"),
            "the AIA id-ad-ocsp URI must be recovered from the leaf"
        );
    }

    #[test]
    fn aia_url_extraction_none_without_aia() {
        // A leaf with no AIA extension yields None → the caller maps to Unknown.
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        assert!(
            extract_ocsp_responder_url(cert.der().as_ref()).is_none(),
            "a leaf without AIA must yield no responder URL"
        );
    }

    #[test]
    fn aia_url_extraction_none_on_garbage() {
        assert!(
            extract_ocsp_responder_url(b"not a certificate").is_none(),
            "unparseable bytes must yield no responder URL"
        );
    }

    #[test]
    fn ocsp_request_der_round_trips() {
        let (issuer_der, _) = mint_issuer();
        // The leaf need not be issued by the issuer; CertID only hashes the
        // issuer subject/key and copies the leaf serial.
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let sent = SentRequest::with_nonce(&leaf, &issuer_der, b"sixteen-byte-non".to_vec())
            .expect("request");
        let decoded = OcspRequest::from_der(sent.der()).expect("request DER round-trips");
        assert_eq!(
            decoded.tbs_request.request_list.len(),
            1,
            "exactly one Request (one CertID) must be present"
        );
    }

    #[test]
    fn nonce_round_trips_in_request() {
        // The live path builds a request WITH a nonce extension; assert it is
        // present and recoverable (so the responder can echo it).
        let leaf = mint_leaf_with_aia("http://x/r");
        let (issuer_der, _) = mint_issuer();
        let nonce = b"sixteen-byte-non".to_vec();
        let sent = SentRequest::with_nonce(&leaf, &issuer_der, nonce.clone()).expect("request");
        let decoded = OcspRequest::from_der(sent.der()).expect("round-trips");
        let echoed = decoded.nonce().expect("nonce present");
        assert_eq!(echoed.0.as_bytes(), nonce.as_slice());
        assert_eq!(sent.nonce(), nonce.as_slice());
    }

    #[test]
    fn ocsp_request_builder_default_is_empty() {
        // Sanity: an empty builder builds a request with no CertIDs (guards
        // against an accidental default CertID).
        let req = OcspRequestBuilder::default().build();
        let der = req.to_der().expect("der");
        let decoded = OcspRequest::from_der(&der).expect("round trip");
        assert!(decoded.tbs_request.request_list.is_empty());
    }
}
