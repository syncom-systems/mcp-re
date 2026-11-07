//! Whether a certificate is a valid DELEGATED OCSP responder for an issuer (RFC 6960
//! §4.2.2.2 / §4.2.2.2.1): the standing a responder certificate must have before its key may
//! sign a response on the issuer's behalf.
//!
//! Pure over certificate bytes and an injected `now`; the cryptographic issuer-signature
//! check is [`super::issuer::cert_is_signed_by`].

use std::time::SystemTime;

use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use super::freshness::system_time_to_unix;
use super::issuer::cert_is_signed_by;
use super::OcspError;

/// The `id-kp-OCSPSigning` extended-key-usage OID (`1.3.6.1.5.5.7.3.9`,
/// RFC 6960 §4.2.2.2). A delegated responder certificate — one carried in the
/// response's `certs` rather than being the issuer itself — MUST carry this EKU
/// for its signature over the response to be trusted.
const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// The `id-pkix-ocsp-nocheck` extension OID (`1.3.6.1.5.5.7.48.1.5`, RFC 6960 §4.2.2.2.1).
/// This module has no revocation source for a delegated responder certificate, so the
/// extension — which licenses a relying party to skip that check — is the only way the
/// responder's standing can be established here.
const ID_PKIX_OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

/// Whether `cert_der` is a valid delegated OCSP responder for `issuer_der` at
/// `now` (RFC 6960 §4.2.2.2 / §4.2.2.2.1): within its own `notBefore`/`notAfter`
/// window, carrying the `id-kp-OCSPSigning` extended key usage and
/// `id-pkix-ocsp-nocheck`, not a CA, permitting `digitalSignature` when it states key
/// usage, and signed by the issuer. An extension that fails to parse refuses. Pure; the
/// cryptographic issuer-signature check is compiled with the `online_ocsp` module exactly
/// as the response-signature check is.
pub(super) fn delegated_responder_is_valid(
    cert_der: &[u8],
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<bool, OcspError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("delegated cert parse: {e}")))?;
    if !is_valid_at(&cert, now) || !declares_ocsp_signing_eku(&cert) {
        return Ok(false);
    }
    if !responder_standing_is_established(&cert) {
        return Ok(false);
    }
    // Must be signed by the issuer.
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("issuer parse: {e}")))?;
    Ok(cert_is_signed_by(&cert, &issuer))
}

/// Whether `cert` is within its own `notBefore`/`notAfter` window at `now`.
///
/// RFC 6960 §4.2.2.2.1: the responder certificate MUST itself be valid at the response
/// time. An expired or not-yet-valid delegated responder (e.g. a rotated-out signer) is
/// not a valid responder, so no candidate key verifies, the caller fails closed (status →
/// Unknown → deny), and a possibly-revoked client is never admitted under a stale signer
/// key. A `now` before the epoch, or one the certificate time type cannot hold, is not
/// inside any window.
fn is_valid_at(cert: &X509Certificate<'_>, now: SystemTime) -> bool {
    let Some(now_unix) = system_time_to_unix(now) else {
        return false;
    };
    let Ok(now_asn1) = ASN1Time::from_timestamp(now_unix.as_secs() as i64) else {
        return false;
    };
    cert.validity().is_valid_at(now_asn1)
}

/// Whether `cert` declares the id-kp-OCSPSigning EKU. x509-parser surfaces it both as the
/// dedicated `ocsp_signing` flag and in `other`; both are checked for robustness.
fn declares_ocsp_signing_eku(cert: &X509Certificate<'_>) -> bool {
    match cert.extended_key_usage() {
        Ok(Some(eku)) => {
            eku.value.ocsp_signing
                || eku
                    .value
                    .other
                    .iter()
                    .any(|oid| oid.to_id_string() == ID_KP_OCSP_SIGNING)
        }
        _ => false,
    }
}

/// Whether a delegated responder certificate's own standing is established: it carries
/// `id-pkix-ocsp-nocheck` (the only licence this module has to skip a revocation check of
/// it), is not a CA, and permits `digitalSignature` when it states key usage.
fn responder_standing_is_established(cert: &X509Certificate<'_>) -> bool {
    let nocheck = cert
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == ID_PKIX_OCSP_NOCHECK);
    let not_a_ca = cert
        .basic_constraints()
        .is_ok_and(|bc| !bc.is_some_and(|bc| bc.value.ca));
    let may_sign = cert
        .key_usage()
        .is_ok_and(|ku| ku.is_none_or(|ku| ku.value.digital_signature()));
    nocheck && not_a_ca && may_sign
}

#[cfg(test)]
mod tests {
    use super::delegated_responder_is_valid;
    use crate::ocsp::issuer::tests::mint_ca_issuer;
    use crate::ocsp::pipeline::tests::at;
    use crate::ocsp::pipeline::tests::ed25519_key;
    use crate::ocsp::pipeline::tests::signed_response_with;
    use crate::ocsp::pipeline::tests::Shape;
    use crate::ocsp::pipeline::tests::Signing;
    use crate::ocsp::pipeline::tests::Target;
    use crate::ocsp::pipeline::tests::Ymd;
    use crate::ocsp::pipeline::tests::REQUEST_NONCE;
    use crate::ocsp::pipeline::verify_and_map_response;
    use crate::ocsp::request::tests::mint_leaf_with_aia;
    use crate::ocsp::CertRevocationStatus;
    use crate::ocsp::OcspError;

    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use der::Decode;
    use ed25519_dalek::SigningKey;
    use rcgen::date_time_ymd;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;
    use x509_cert::Certificate;
    use x509_ocsp::CertStatus;

    /// A `SystemTime` `secs` after the Unix epoch (test helper).
    pub(in crate::ocsp) fn at_unix(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// What a delegated responder certificate carries, for the standing tests.
    #[derive(Clone)]
    pub(in crate::ocsp) struct ResponderShape {
        pub(in crate::ocsp) ocsp_signing_eku: bool,
        pub(in crate::ocsp) nocheck: bool,
        pub(in crate::ocsp) ca: bool,
        pub(in crate::ocsp) key_usages: Vec<rcgen::KeyUsagePurpose>,
    }

    impl ResponderShape {
        /// A well-formed delegated responder: EKU and nocheck, not a CA, no key usage stated.
        pub(in crate::ocsp) fn proper() -> Self {
            ResponderShape {
                ocsp_signing_eku: true,
                nocheck: true,
                ca: false,
                key_usages: Vec::new(),
            }
        }
    }

    /// A validity window as `(year, month, day)` triples, `[not_before, not_after)`.
    #[derive(Clone, Copy)]
    pub(in crate::ocsp) struct Window {
        pub(in crate::ocsp) not_before: (i32, u8, u8),
        pub(in crate::ocsp) not_after: (i32, u8, u8),
    }

    /// The window the delegated-responder tests mint inside: 2020-01-01 to 2021-01-01.
    pub(in crate::ocsp) const WINDOW_2020: Window = Window {
        not_before: (2020, 1, 1),
        not_after: (2021, 1, 1),
    };

    /// Mint a delegated OCSP responder cert SIGNED BY `issuer` over its own key, shaped by
    /// `shape`, valid over `window`.
    pub(in crate::ocsp) fn mint_responder_with(
        issuer: &rcgen::Issuer<'_, KeyPair>,
        responder_key: &KeyPair,
        shape: &ResponderShape,
        window: Window,
    ) -> Vec<u8> {
        let mut params =
            CertificateParams::new(vec!["ocsp-responder.example".to_string()]).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "ocsp-responder.example");
        let (nb, na) = (window.not_before, window.not_after);
        params.not_before = date_time_ymd(nb.0, nb.1, nb.2);
        params.not_after = date_time_ymd(na.0, na.1, na.2);
        if shape.ocsp_signing_eku {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::OcspSigning);
        }
        if shape.nocheck {
            // id-pkix-ocsp-nocheck, value NULL.
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
                    vec![0x05, 0x00],
                ));
        }
        if shape.ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        params.key_usages = shape.key_usages.clone();
        let cert = params
            .signed_by(responder_key, issuer)
            .expect("responder signed by issuer");
        cert.der().as_ref().to_vec()
    }

    /// A well-formed delegated OCSP responder cert (see [`ResponderShape::proper`]).
    pub(in crate::ocsp) fn mint_delegated_responder(
        issuer: &rcgen::Issuer<'_, KeyPair>,
        window: Window,
    ) -> Vec<u8> {
        let key = KeyPair::generate().expect("responder key");
        mint_responder_with(issuer, &key, &ResponderShape::proper(), window)
    }

    /// 2020-07-01, inside `WINDOW_2020`.
    const INSIDE_2020: u64 = 1_593_561_600;

    /// RFC 6960 §4.2.2.2.1: a delegated responder cert OUTSIDE its validity window
    /// is rejected (fail closed — no candidate verifies → deny), while the same
    /// cert WITHIN its window and issuer-signed is accepted. Locks the M-95
    /// validity-window check.
    #[test]
    fn delegated_responder_validity_window_enforced() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let responder_der = mint_delegated_responder(&issuer, WINDOW_2020);
        let valid_at = |secs: u64| {
            delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(secs)).unwrap()
        };

        assert!(
            valid_at(INSIDE_2020),
            "in-window, issuer-signed, OCSP-EKU responder must be accepted"
        );
        assert!(
            !valid_at(1_640_995_200), // 2022-01-01, after notAfter
            "an EXPIRED delegated responder cert must be rejected (RFC 6960 §4.2.2.2.1)"
        );
        assert!(
            !valid_at(1_546_300_800), // 2019-01-01, before notBefore
            "a not-yet-valid delegated responder cert must be rejected"
        );
    }

    /// RFC 6960 §4.2.2.2.1: this module has no revocation source for a delegated responder,
    /// so a responder certificate without `id-pkix-ocsp-nocheck` has no established standing.
    #[test]
    fn delegated_responder_without_nocheck_is_refused() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let key = KeyPair::generate().expect("responder key");
        let shape = ResponderShape {
            nocheck: false,
            ..ResponderShape::proper()
        };
        let responder = mint_responder_with(&issuer, &key, &shape, WINDOW_2020);
        assert!(
            !delegated_responder_is_valid(&responder, &issuer_der, at_unix(INSIDE_2020)).unwrap(),
            "an in-window, issuer-signed, OCSP-EKU responder lacking nocheck must be refused"
        );
    }

    /// A delegated responder that is itself a CA, or whose stated key usage does not permit
    /// `digitalSignature`, is not a signer of OCSP responses.
    #[test]
    fn delegated_responder_that_is_a_ca_or_lacks_digital_signature_is_refused() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let key = KeyPair::generate().expect("responder key");
        let now = at_unix(INSIDE_2020);
        let is_valid = |shape: &ResponderShape| {
            let responder = mint_responder_with(&issuer, &key, shape, WINDOW_2020);
            delegated_responder_is_valid(&responder, &issuer_der, now).unwrap()
        };
        for (label, shape) in [
            (
                "a CA",
                ResponderShape {
                    ca: true,
                    ..ResponderShape::proper()
                },
            ),
            (
                "key usage without digitalSignature",
                ResponderShape {
                    key_usages: vec![rcgen::KeyUsagePurpose::KeyEncipherment],
                    ..ResponderShape::proper()
                },
            ),
        ] {
            assert!(
                !is_valid(&shape),
                "a responder that is {label} must be refused"
            );
        }
        let signing = ResponderShape {
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            ..ResponderShape::proper()
        };
        assert!(
            is_valid(&signing),
            "the positive control: digitalSignature key usage is admitted"
        );
    }

    /// A CA, an Ed25519 delegated responder it signed, and the key that signs responses.
    fn delegated_responder(shape: &ResponderShape) -> (Vec<u8>, SigningKey, Vec<u8>) {
        let ca_signer = SigningKey::from_bytes(&[7u8; 32]);
        let ca_key = ed25519_key(&ca_signer);
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-ed25519-ca");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_der = ca_params
            .self_signed(&ca_key)
            .expect("ca self-signed")
            .der()
            .as_ref()
            .to_vec();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let responder_signer = SigningKey::from_bytes(&[11u8; 32]);
        let responder_der = mint_responder_with(
            &issuer,
            &ed25519_key(&responder_signer),
            shape,
            Window {
                not_before: (2023, 1, 1),
                not_after: (2025, 1, 1),
            },
        );
        (ca_der, responder_signer, responder_der)
    }

    fn delegated_response(shape: &ResponderShape) -> Result<CertRevocationStatus, OcspError> {
        let (ca_der, responder_signer, responder_der) = delegated_responder(shape);
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let target = Target {
            issuer_der: &ca_der,
            leaf_der: &leaf,
        };
        let response = signed_response_with(
            &Signing {
                key: &responder_signer,
                cert_der: &responder_der,
            },
            &target,
            CertStatus::good(),
            Shape {
                certs: Some(vec![
                    Certificate::from_der(&responder_der).expect("responder cert")
                ]),
                ..Shape::default()
            },
        );
        verify_and_map_response(&response, &target.sent(REQUEST_NONCE), at(Ymd(2024, 1, 1)))
            .map(|answer| answer.status())
    }

    /// The delegated-responder ADMIT path end to end: the response is signed by a responder
    /// certificate the CA issued, which names it, carries the OCSP-signing EKU and nocheck.
    #[test]
    fn delegated_responder_signed_good_is_admitted() {
        assert_eq!(
            delegated_response(&ResponderShape::proper()).expect("a delegated Good verifies"),
            CertRevocationStatus::Good
        );
    }

    /// Each requirement on the delegated responder is load-bearing: dropping the EKU (the
    /// gap EX-006 names) or nocheck turns the admitted response into a denial.
    #[test]
    fn a_delegated_responder_missing_a_requirement_is_denied() {
        for (label, shape) in [
            (
                "the OCSP-signing EKU",
                ResponderShape {
                    ocsp_signing_eku: false,
                    ..ResponderShape::proper()
                },
            ),
            (
                "id-pkix-ocsp-nocheck",
                ResponderShape {
                    nocheck: false,
                    ..ResponderShape::proper()
                },
            ),
        ] {
            let result = delegated_response(&shape);
            assert!(
                matches!(result, Err(OcspError::SignatureNotVerified(_))),
                "a delegated responder without {label} must be denied, got {result:?}"
            );
        }
    }
}
