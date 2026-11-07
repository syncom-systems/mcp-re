// SPDX-License-Identifier: Apache-2.0
//! The harness's key material: certificate authorities, leaves, and the files the proxy reads.

use super::*;

// --- rcgen certificate authority + leaves -------------------------------------

pub(super) struct Ca {
    pub(super) cert: rcgen::Certificate,
    pub(super) key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the
    /// issuer DN, key-identifier method and key usages from these, not from `cert`.
    pub(super) params: CertificateParams,
}

impl Ca {
    /// The issuing state that minted `cert`, paired with the signing key.
    pub(super) fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-loadgen-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

pub(super) fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (cert, key)
}

/// Mint a CLIENT leaf whose validity SPAN is within the proxy's enforced ceiling
/// (`MAX_CLIENT_CERT_LIFETIME`) AND is currently valid, so the proxy's cert-lifetime
/// guard accepts it. The span is derived from the SAME constant the proxy enforces
/// (one source of truth) — no fixture hardcodes a lifetime to dodge the guard.
/// Valid from ~1min ago to (ceiling − 2min) ahead: span = ceiling − 60s < ceiling.
pub(super) fn make_client_leaf(ca: &Ca, sans: Vec<SanType>) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    let now = time::OffsetDateTime::now_utc();
    let ceiling = time::Duration::seconds(MAX_CLIENT_CERT_LIFETIME.as_secs() as i64);
    params.not_before = now - time::Duration::seconds(60);
    params.not_after = now + ceiling - time::Duration::seconds(120);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (cert, key)
}

/// Write an EMPTY, far-future CRL signed by `ca` to `path` (DER). Empty = revokes
/// nothing (the client stays valid), far-future `nextUpdate` = not stale (the proxy
/// refuses to start on a stale CRL). Used to drive the `--client-crl` + hot-reload
/// path in-process.
pub(super) fn write_empty_crl(ca: &Ca, path: &std::path::Path) {
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        next_update: rcgen::date_time_ymd(2999, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params.signed_by(&ca.issuer()).expect("crl signed");
    std::fs::write(path, crl.der()).expect("write crl");
}

pub(super) fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// --- temp key material on disk ------------------------------------------------

pub(super) fn tmp(name: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "mcp_re_loadgen_{}_{seq}_{name}",
        std::process::id()
    ))
}

pub(super) struct Material {
    pub(super) seed_path: PathBuf,
    pub(super) server_cert_path: PathBuf,
    pub(super) server_key_path: PathBuf,
    pub(super) client_ca_path: PathBuf,
    pub(super) trust_path: PathBuf,
    pub(super) client_ca: Ca,
    /// DER of the CA that issued the server leaf; clients verify the server against it.
    pub(super) server_root: CertificateDer<'static>,
}

pub(super) fn write_material() -> Material {
    let server_ca = make_ca();
    let (server_leaf, server_leaf_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let client_ca = make_ca();
    let server_root = server_ca.cert.der().clone();

    let seed_path = tmp("seed");
    let server_cert_path = tmp("server_cert.pem");
    let server_key_path = tmp("server_key.pem");
    let client_ca_path = tmp("client_ca.pem");
    let trust_path = tmp("trust.json");

    std::fs::write(&seed_path, b64url_encode(&server_seed())).unwrap();
    std::fs::write(&server_cert_path, server_leaf.pem()).unwrap();
    std::fs::write(&server_key_path, server_leaf_key.serialize_pem()).unwrap();
    std::fs::write(&client_ca_path, client_ca.cert.pem()).unwrap();
    // The proxy refuses to start on a group/world-accessible sensitive key file, so
    // the fixture must restrict the signing-key seed and the TLS server key to 0600
    // (owner-only) — the same posture a production deployment uses.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&seed_path, &server_key_path] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    // The RFC 9421 trust file maps the request-signer keyid → (signer, public_key).
    let trust = json!([
        { "signer": SUBJECT_A, "key_id": SIGNER_A_KEY_ID, "public_key": signer_a_key().public_key().to_b64url() },
    ]);
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();

    Material {
        seed_path,
        server_cert_path,
        server_key_path,
        client_ca_path,
        trust_path,
        client_ca,
        server_root,
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        for p in [
            &self.seed_path,
            &self.server_cert_path,
            &self.server_key_path,
            &self.client_ca_path,
            &self.trust_path,
        ] {
            let _ = std::fs::remove_file(p);
        }
    }
}
