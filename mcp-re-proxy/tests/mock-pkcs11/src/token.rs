//! Building the mock token from the environment: the token label and the key objects the
//! test asked for.

use std::collections::HashMap;

use cryptoki_sys::CKK_EC;
use cryptoki_sys::CKK_EC_EDWARDS;
use cryptoki_sys::CKO_PRIVATE_KEY;
use cryptoki_sys::CKO_PUBLIC_KEY;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_OBJECT_HANDLE;
use ed25519_dalek::SigningKey;
use sha2::Digest;
use sha2::Sha256;

use super::state::KeyObject;
use super::state::State;

/// What one `label,keytype,id` entry stands for, before it becomes objects.
struct KeyMaterial {
    key_type: CK_KEY_TYPE,
    signing: Option<SigningKey>,
    /// The 32-byte point the objects advertise.
    point: Vec<u8>,
    exportable: bool,
}

impl State {
    /// Build the token from `MOCK_PKCS11_TOKEN_LABEL` + `MOCK_PKCS11_OBJECTS`.
    pub(crate) fn from_env() -> State {
        let token_label =
            std::env::var("MOCK_PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "mcp-re-test".to_string());
        let spec = std::env::var("MOCK_PKCS11_OBJECTS").unwrap_or_default();

        let mut objects: Vec<KeyObject> = Vec::new();
        for entry in spec.split(';').filter(|e| !e.trim().is_empty()) {
            let first_handle = objects.len() as CK_OBJECT_HANDLE + 1;
            objects.extend(key_pair(entry, first_handle));
        }

        State {
            token_label,
            objects,
            sessions: HashMap::new(),
            next_session: 1,
            logged_in: false,
        }
    }
}

/// A generated key pair is TWO objects (private + public) sharing label/id.
fn key_pair(entry: &str, first_handle: CK_OBJECT_HANDLE) -> Vec<KeyObject> {
    let parts: Vec<&str> = entry.split(',').collect();
    assert!(
        parts.len() == 3,
        "MOCK_PKCS11_OBJECTS entry must be `label,keytype,id`, got {entry:?}"
    );
    let (label, keytype, id) = (parts[0], parts[1], parts[2]);
    let material = key_material(label, keytype, id);
    let ec_point = der_octet_string(&material.point);
    [CKO_PRIVATE_KEY, CKO_PUBLIC_KEY]
        .into_iter()
        .zip(first_handle..)
        .map(|(class, handle)| KeyObject {
            handle,
            class,
            key_type: material.key_type,
            label: label.as_bytes().to_vec(),
            // Only the private object needs to sign; the public one carries
            // the point. Cloning the signer keeps both self-consistent.
            signing: material.signing.clone(),
            ec_point: ec_point.clone(),
            exportable: material.exportable,
        })
        .collect()
}

fn key_material(label: &str, keytype: &str, id: &str) -> KeyMaterial {
    let exportable = keytype == "ed25519-extractable";
    let (key_type, signing, point) = match keytype {
        "ed25519" | "ed25519-extractable" => {
            let sk = derive_signing_key(label, id);
            let point = sk.verifying_key().to_bytes().to_vec();
            (CKK_EC_EDWARDS, Some(sk), point)
        }
        // Both objects advertise the point of `derive_signing_key(label, id)`, but
        // the private object signs with a DIFFERENT key: `C_Sign` returns 64
        // well-formed bytes that verify under no advertised key.
        "ed25519-misbound" => {
            let advertised = derive_signing_key(label, id);
            let point = advertised.verifying_key().to_bytes().to_vec();
            let signer = derive_signing_key(label, &format!("{id}-misbound"));
            (CKK_EC_EDWARDS, Some(signer), point)
        }
        // A non-Ed25519 object: it exists so the client's Ed25519-typed
        // find never matches it (proving a non-Ed25519 TLS key is rejected).
        // It is never signed with, so no key material is needed.
        "ec" => (CKK_EC, None, vec![0u8; 32]),
        other => panic!("MOCK_PKCS11_OBJECTS unknown keytype {other:?}"),
    };
    KeyMaterial {
        key_type,
        signing,
        point,
        exportable,
    }
}

/// Deterministic Ed25519 key from `SHA-256(label || 0x00 || id)`. Distinct
/// (label, id) pairs yield distinct keys; the same pair is stable across re-inits.
fn derive_signing_key(label: &str, id: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0u8]);
    hasher.update(id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Wrap a 32-byte Edwards point as the DER `OCTET STRING` a token returns for
/// `CKA_EC_POINT`: `0x04 <len> <point>`.
fn der_octet_string(point: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.len() + 2);
    out.push(0x04);
    out.push(point.len() as u8);
    out.extend_from_slice(point);
    out
}
