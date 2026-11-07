// SPDX-License-Identifier: Apache-2.0
//! The fixture material the three tiers share: a server certificate chain, a client
//! certificate chain, the proxy's signing seed and the trust document naming the signer.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use mcp_re_core::SigningKey;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use serde_json::json;

const SUBJECT_A: &str = "did:example:agent-1";
const SIGNER_A_KEY_ID: &str = "key-a";
/// The client leaf's URI SAN. It is the request actor's SUBJECT, because that is the
/// operand the serving path binds the channel to: `bind_request_to_peer` compares the
/// peer identity extracted from the leaf against `VerifiedRequestSubject`, which is
/// `ResolvedActor::identity.subject` and nothing else. Any other encoding of the actor
/// is refused `mcp-re.transport_binding_failed` before the request reaches the backend,
/// and the rig then measures nothing at all — which is what `--smoke` exists to catch.
const CLIENT_ACTOR_ID: &str = SUBJECT_A;
pub(super) const MAX_CLIENT_CERT_LIFETIME_SECS: u64 = 3600;

pub(super) fn tmp(name: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("mcp_re_sat_{}_{seq}_{name}", std::process::id()))
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn mint() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-sat-ca");
        let cert = params.self_signed(&key).expect("self-signed");
        Ca { cert, key, params }
    }

    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

struct Leaf {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Leaf {
    fn sign(ca: &Ca, mut params: CertificateParams, usage: ExtendedKeyUsagePurpose) -> Self {
        let key = KeyPair::generate().expect("leaf key");
        params.extended_key_usages = vec![usage];
        let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
        Leaf { cert, key }
    }

    fn server(ca: &Ca) -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("dns"))];
        Self::sign(ca, params, ExtendedKeyUsagePurpose::ServerAuth)
    }

    fn client(ca: &Ca) -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::URI(CLIENT_ACTOR_ID.try_into().expect("uri san"))];
        // Minted INSIDE the proxy's enforced ceiling: the serving path rejects a client
        // certificate whose span exceeds --max-client-cert-lifetime.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::seconds(60);
        params.not_after = now + time::Duration::seconds(MAX_CLIENT_CERT_LIFETIME_SECS as i64)
            - time::Duration::seconds(120);
        Self::sign(ca, params, ExtendedKeyUsagePurpose::ClientAuth)
    }
}

/// The two certificate chains, before any of them is written to disk.
struct Pki {
    server_ca: Ca,
    server_leaf: Leaf,
    client_ca: Ca,
    client_leaf: Leaf,
}

impl Pki {
    fn mint() -> Self {
        let server_ca = Ca::mint();
        let server_leaf = Leaf::server(&server_ca);
        let client_ca = Ca::mint();
        let client_leaf = Leaf::client(&client_ca);
        Pki {
            server_ca,
            server_leaf,
            client_ca,
            client_leaf,
        }
    }
}

pub(super) struct Material {
    pub(super) seed: PathBuf,
    pub(super) server_cert: PathBuf,
    pub(super) server_key: PathBuf,
    pub(super) client_ca: PathBuf,
    pub(super) trust: PathBuf,
    pub(super) client_leaf_der: PathBuf,
    pub(super) client_key_der: PathBuf,
    /// DER of the CA that issued the server leaf, which the generator verifies the proxy against.
    pub(super) server_ca_der: PathBuf,
}

impl Material {
    fn allocate() -> Self {
        Material {
            seed: tmp("seed"),
            server_cert: tmp("server_cert.pem"),
            server_key: tmp("server_key.pem"),
            client_ca: tmp("client_ca.pem"),
            trust: tmp("trust.json"),
            client_leaf_der: tmp("client_leaf.der"),
            client_key_der: tmp("client_key.der"),
            server_ca_der: tmp("server_ca.der"),
        }
    }

    fn write_pki(&self, pki: &Pki) {
        std::fs::write(&self.seed, b64url(&[2u8; 32])).expect("seed");
        std::fs::write(&self.server_cert, pki.server_leaf.cert.pem()).expect("server cert");
        std::fs::write(&self.server_key, pki.server_leaf.key.serialize_pem()).expect("server key");
        std::fs::write(&self.client_ca, pki.client_ca.cert.pem()).expect("client ca");
        // DER for the generator, so it needs no PEM parser.
        std::fs::write(&self.client_leaf_der, pki.client_leaf.cert.der().as_ref())
            .expect("client leaf der");
        std::fs::write(&self.client_key_der, pki.client_leaf.key.serialize_der())
            .expect("client key der");
        std::fs::write(&self.server_ca_der, pki.server_ca.cert.der().as_ref())
            .expect("server ca der");
    }

    /// The proxy refuses to start on a group/world-readable key.
    #[cfg(unix)]
    fn restrict_key_permissions(&self) {
        use std::os::unix::fs::PermissionsExt;
        for p in [&self.seed, &self.server_key] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }

    #[cfg(not(unix))]
    fn restrict_key_permissions(&self) {}

    fn write_trust(&self) {
        let signer = SigningKey::from_seed_bytes(&[1u8; 32]);
        let trust = json!([{
            "signer": SUBJECT_A,
            "key_id": SIGNER_A_KEY_ID,
            "public_key": signer.public_key().to_b64url(),
        }]);
        std::fs::write(&self.trust, serde_json::to_vec(&trust).expect("trust json"))
            .expect("trust");
    }
}

pub(super) fn write_material() -> Material {
    let pki = Pki::mint();
    let m = Material::allocate();
    m.write_pki(&pki);
    m.restrict_key_permissions();
    m.write_trust();
    m
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..(c.len() + 1) {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
