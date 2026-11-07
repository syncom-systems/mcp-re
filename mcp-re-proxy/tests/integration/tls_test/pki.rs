//! Certificates minted in-process with `rcgen`: a test CA, its leaves, and its CRLs.
//! No private key is committed.

use std::time::Duration;

use mcp_re_proxy::config_state::ClientCredentialWindow;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::CertificateRevocationListParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyIdMethod;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::RevocationReason;
use rcgen::RevokedCertParams;
use rcgen::SanType;
use rcgen::SerialNumber;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;

/// A calendar date at day granularity: `(year, month, day)`.
pub(super) type Ymd = (i32, u8, u8);

/// A certificate validity window at day granularity, so a leaf's lifetime is
/// deterministic for max-lifetime enforcement tests.
pub(super) struct Validity {
    pub(super) not_before: Ymd,
    pub(super) not_after: Ymd,
}

/// The credential window every served test deployment states.
pub(super) fn window() -> ClientCredentialWindow {
    ClientCredentialWindow::new(Duration::from_secs(3600), Duration::from_secs(300))
        .expect("a legal credential window")
}

/// Validity `[now - 60s, now + 1800s]`: inside the window, so a served request finds the
/// leaf current.
fn short_lived(params: &mut CertificateParams) {
    params.not_before = (std::time::SystemTime::now() - Duration::from_secs(60)).into();
    params.not_after = (std::time::SystemTime::now() + Duration::from_secs(1800)).into();
}

pub(super) struct Ca {
    pub(super) cert: rcgen::Certificate,
    key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the
    /// issuer DN, key-identifier method and key usages from these, not from `cert`.
    params: CertificateParams,
}

impl Ca {
    /// The issuing state that minted `cert`, paired with the signing key.
    pub(super) fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }

    /// The CA certificate's DER, as a trust anchor.
    pub(super) fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }
}

pub(super) fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

/// Sign `params` with `key` under `ca`, returning the leaf DER and its PKCS#8 key.
fn sign_leaf(
    ca: &Ca,
    params: &CertificateParams,
    key: &KeyPair,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = params.signed_by(key, &ca.issuer()).expect("leaf signed");
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert.der().clone(), key_der)
}

fn leaf_params(sans: Vec<SanType>, eku: ExtendedKeyUsagePurpose) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    params.extended_key_usages = vec![eku];
    params
}

/// A leaf signed by `ca`, with the given SANs / CN and (client or server) EKU.
pub(super) fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let eku = if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    };
    let mut params = leaf_params(sans, eku);
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    if client_auth {
        short_lived(&mut params);
    }
    sign_leaf(ca, &params, &KeyPair::generate().expect("leaf key"))
}

/// A client leaf with an explicit validity window, so its lifetime is deterministic.
pub(super) fn make_client_leaf_valid_between(
    ca: &Ca,
    sans: Vec<SanType>,
    validity: &Validity,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = leaf_params(sans, ExtendedKeyUsagePurpose::ClientAuth);
    let (y, m, d) = validity.not_before;
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = validity.not_after;
    params.not_after = rcgen::date_time_ymd(y, m, d);
    sign_leaf(ca, &params, &KeyPair::generate().expect("leaf key"))
}

/// A client leaf signed by `ca` with an EXPLICIT serial number, so a CRL can be
/// minted that revokes exactly this certificate (#3839).
pub(super) fn make_client_leaf_with_serial(
    ca: &Ca,
    san: &str,
    serial: u64,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = leaf_params(vec![uri(san)], ExtendedKeyUsagePurpose::ClientAuth);
    params.serial_number = Some(SerialNumber::from(serial));
    short_lived(&mut params);
    sign_leaf(ca, &params, &KeyPair::generate().expect("leaf key"))
}

/// Mint a server leaf for `localhost` with the given key algorithm, signed by `ca`.
pub(super) fn make_localhost_server_leaf(ca: &Ca, key: &KeyPair) -> CertificateDer<'static> {
    let mut params = leaf_params(vec![dns("localhost")], ExtendedKeyUsagePurpose::ServerAuth);
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    sign_leaf(ca, &params, key).0
}

/// Mint a CRL signed by `ca` that revokes the certificates with the given serials
/// (#3839). The CA carries `CrlSign` key usage (see `make_ca`), which rcgen
/// requires of a CRL issuer. Returns the CRL in the DER form rustls consumes.
pub(super) fn make_crl(ca: &Ca, revoked_serials: &[u64]) -> CertificateRevocationListDer<'static> {
    // A far-future nextUpdate (2999): well-formed and never stale, so the existing
    // revocation tests exercise the revoked-vs-not path independently of the
    // ADR-MCPS-023 §A1 (MCPS-58) nextUpdate-expiration enforcement.
    make_crl_full(ca, revoked_serials, (2024, 1, 1), (2999, 1, 1))
}

/// Mint a CRL signed by `ca` with explicit `thisUpdate` / `nextUpdate` dates, so a
/// STALE CRL (nextUpdate in the past) can be constructed to exercise the
/// ADR-MCPS-023 §A1 (MCPS-58) fail-closed-on-stale enforcement.
pub(super) fn make_crl_full(
    ca: &Ca,
    revoked_serials: &[u64],
    this_update_ymd: Ymd,
    next_update_ymd: Ymd,
) -> CertificateRevocationListDer<'static> {
    let this_update = rcgen::date_time_ymd(this_update_ymd.0, this_update_ymd.1, this_update_ymd.2);
    let next_update = rcgen::date_time_ymd(next_update_ymd.0, next_update_ymd.1, next_update_ymd.2);
    let revoked_certs = revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: this_update,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params.signed_by(&ca.issuer()).expect("crl signed by ca");
    crl.der().clone()
}

pub(super) fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}

pub(super) fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}
