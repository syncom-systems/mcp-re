//! Delegated TLS handshake signers (ADR-MCPS-028 §G) and the server leaves they stand in
//! for. The server's TLS key is NOT exported to rustls: a `RawEd25519TlsSigner` (here a
//! local Ed25519 key standing in for a PKCS#11 token / KMS) signs each handshake.

use rcgen::KeyPair;

use rustls_pki_types::CertificateDer;

use super::pki::make_localhost_server_leaf;
use super::pki::Ca;

/// A delegated signer backed by a LOCAL Ed25519 key (stand-in for device/KMS):
/// signs the raw handshake transcript exactly as a KMS RAW `Sign` would.
#[derive(Debug)]
pub(super) struct LocalEd25519Tls(pub(super) mcp_re_core::SigningKey);

impl LocalEd25519Tls {
    /// A signer over the key whose 32-byte seed is `seed` repeated. Its public key is
    /// independent of every leaf minted here, so it cannot match one: it drives the
    /// cert↔signer mismatch fail-closed path.
    pub(super) fn from_repeated_seed_byte(seed: u8) -> Self {
        Self(mcp_re_core::SigningKey::from_seed_bytes(&[seed; 32]))
    }
}

impl mcp_re_proxy::RawEd25519TlsSigner for LocalEd25519Tls {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcp_re_proxy::KeyError> {
        Ok(mcp_re_core::b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
    }
    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcp_re_proxy::KeyError> {
        Ok(ed25519_spki_from_raw(&self.0.public_key().to_bytes()))
    }
}

/// A signer that flips a bit of every raw signature. It reports the SAME public key as
/// the honest signer it wraps, so the cert↔signer check still passes, the build
/// succeeds, and the BREAK is at the handshake.
#[derive(Debug)]
pub(super) struct CorruptingEd25519Tls(pub(super) LocalEd25519Tls);

impl mcp_re_proxy::RawEd25519TlsSigner for CorruptingEd25519Tls {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, mcp_re_proxy::KeyError> {
        let mut sig = self.0.sign_tls_ed25519(message)?;
        sig[0] ^= 0x01; // corrupt one bit — the signature no longer verifies
        Ok(sig)
    }
    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, mcp_re_proxy::KeyError> {
        self.0.tls_public_key_spki_der()
    }
}

/// The fixed 12-byte RFC 8410 Ed25519 `SubjectPublicKeyInfo` prefix, the same one
/// the production SPKI parser anchors on. Building an SPKI from a raw point here
/// (mirroring what AWS/GCP KMS return) keeps the test signer's exported public key
/// in the exact wire form the validated build path parses.
const ED25519_TEST_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn ed25519_spki_from_raw(raw: &[u8; 32]) -> Vec<u8> {
    let mut der = ED25519_TEST_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw);
    der
}

/// The `PrivateKeyInfo` bytes `[5..16]` of an rcgen Ed25519 PKCS#8 key: the Ed25519 OID,
/// then the `04 22` private-key wrapper and `04 20` inner OCTET STRING, which directly
/// precede the seed.
const ED25519_SEED_HEADER: [u8; 11] = [
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The 32-byte seed of an rcgen Ed25519 PKCS#8 key.
///
/// RFC 8410 PKCS#8 Ed25519: the seed sits at bytes `[16..48]`, immediately after the
/// Ed25519 AlgorithmIdentifier + OCTET-STRING headers. The outer SEQUENCE length and
/// version vary (rcgen emits the v2 form WITH the public key appended, ~83 bytes), but
/// the header bytes are invariant. Anchoring on them makes a future rcgen encoding
/// change fail closed with a clear error rather than silently slicing the wrong bytes.
fn ed25519_seed_from_pkcs8(pkcs8: &[u8]) -> [u8; 32] {
    assert!(
        pkcs8.len() >= 48,
        "expected an Ed25519 PKCS#8 key of at least 48 bytes, got {}",
        pkcs8.len()
    );
    assert_eq!(
        &pkcs8[5..16],
        &ED25519_SEED_HEADER,
        "unexpected Ed25519 PKCS#8 header; rcgen encoding may have changed"
    );
    pkcs8[16..48].try_into().expect("ed25519 pkcs8 seed")
}

/// Mint an Ed25519 server leaf signed by `ca`, returning the cert plus the local
/// delegated signer whose key is the cert's key.
pub(super) fn make_ed25519_server_leaf(ca: &Ca) -> (CertificateDer<'static>, LocalEd25519Tls) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
    let der = make_localhost_server_leaf(ca, &key);
    let seed = ed25519_seed_from_pkcs8(&key.serialize_der());
    (
        der,
        LocalEd25519Tls(mcp_re_core::SigningKey::from_seed_bytes(&seed)),
    )
}

/// Mint an ECDSA (NIST P-256) server leaf signed by `ca` — a NON-Ed25519 leaf used
/// to drive the Ed25519-only fail-closed path of the validated delegated builder.
pub(super) fn make_ecdsa_server_leaf(ca: &Ca) -> CertificateDer<'static> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa key");
    make_localhost_server_leaf(ca, &key)
}
