// SPDX-License-Identifier: Apache-2.0
//! Certificate authorities the handshake controls issue from.

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rustls_pki_types::CertificateDer;

pub(crate) struct Ca {
    pub(crate) cert: rcgen::Certificate,
    pub(crate) key: KeyPair,
    pub(crate) params: CertificateParams,
}

impl Ca {
    pub(crate) fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
    pub(crate) fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }
}

pub(crate) fn make_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

/// A CA certificate issued BY another CA, carrying its own identity-bearing field.
///
/// The decoy in the provenance controls: an intermediate whose URI SAN names a different
/// identity from the leaf's, so a derivation that reads "some certificate in the chain"
/// rather than "the leaf" returns the wrong identity instead of merely a different-looking
/// success.
pub(crate) fn make_intermediate(root: &Ca, cn: &str, uri_san: &str) -> Ca {
    let key = KeyPair::generate().expect("intermediate key");
    let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = vec![SanType::URI(uri_san.try_into().expect("uri san"))];
    let cert = params
        .signed_by(&key, &root.issuer())
        .expect("intermediate signed");
    Ca { cert, key, params }
}
