// SPDX-License-Identifier: Apache-2.0
//! End-entity certificates the handshake controls present.
#![cfg(test)]

use std::time::Duration;
use std::time::SystemTime;

use rcgen::CertificateParams;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::KeyPair;
use rcgen::SanType;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;

use super::authority::Ca;

/// The validity window a leaf is issued with.
#[derive(Clone, Copy)]
pub(super) enum Validity {
    /// The generator's default window.
    Default,
    /// `[now - 60s, now + 1800s]`, inside any credential window a deployment can state, so
    /// a verifier running at the real clock finds the leaf current.
    ShortLived,
}

/// One leaf issued by `ca` for `san` and `usage`.
pub(super) fn issue_leaf(
    ca: &Ca,
    san: SanType,
    usage: ExtendedKeyUsagePurpose,
    validity: Validity,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![san];
    params.extended_key_usages = vec![usage];
    if matches!(validity, Validity::ShortLived) {
        params.not_before = (SystemTime::now() - Duration::from_secs(60)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(1800)).into();
    }
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

fn dns_san(name: &str) -> SanType {
    SanType::DnsName(name.try_into().expect("dns san"))
}

fn uri_san(uri: &str) -> SanType {
    SanType::URI(uri.try_into().expect("uri san"))
}

/// A DNS-named leaf, for client authentication or for server authentication.
pub(crate) fn make_leaf(
    ca: &Ca,
    san: &str,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    dns_leaf(ca, san, client_auth, Validity::Default)
}

/// [`make_leaf`] with the window chosen.
pub(super) fn dns_leaf(
    ca: &Ca,
    san: &str,
    client_auth: bool,
    validity: Validity,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let usage = if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    };
    issue_leaf(ca, dns_san(san), usage, validity)
}

/// A client leaf whose identity is a URI SAN — the field the default policy configures.
pub(crate) fn make_uri_leaf(
    ca: &Ca,
    uri: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    uri_leaf(ca, uri, Validity::Default)
}

/// [`make_uri_leaf`] with a validity window around the present moment.
pub(crate) fn make_short_lived_uri_leaf(
    ca: &Ca,
    uri: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    uri_leaf(ca, uri, Validity::ShortLived)
}

fn uri_leaf(
    ca: &Ca,
    uri: &str,
    validity: Validity,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    issue_leaf(
        ca,
        uri_san(uri),
        ExtendedKeyUsagePurpose::ClientAuth,
        validity,
    )
}
