// SPDX-License-Identifier: Apache-2.0
//! The PKCS#11 token-backed key source (#4034).

#[cfg(feature = "pkcs11_keysource")]
use super::pin::read_pkcs11_pin;
use super::Opening;
use crate::key_source::{KeyError, KeySource};

/// The token the custody names: its module, the file holding the User PIN, and the labels
/// of the signing key's token and object.
///
/// Read only by the build that has the backend; the default build refuses before looking.
#[cfg_attr(not(feature = "pkcs11_keysource"), allow(dead_code))]
pub(super) struct Token<'a> {
    pub(super) module: &'a str,
    pub(super) pin_file: &'a str,
    pub(super) token_label: &'a str,
    pub(super) key_label: &'a str,
}

/// Open a source whose signing key lives on a token.
///
/// The state carries all four values, so there is nothing to unwrap and no arm for
/// material that went missing.
#[cfg(feature = "pkcs11_keysource")]
pub(super) fn open(
    opening: Opening<'_, '_>,
    token: Token<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let Opening {
        admitted,
        channel,
        material,
    } = opening;
    // Read the User PIN here, at the one point it is used, so it never lands in
    // `DeploymentRequest` (which is `Debug` and freely cloned); the token keeps its own
    // scrubbed copy for re-login. The PIN comes from the file the custody check admitted, which held
    // it to the key-file floor: it unlocks the token holding the signing keys.
    let pin = read_pkcs11_pin(admitted.take(token.pin_file)?)?;
    let tls_key = super::exported_tls_key(admitted, material)?;
    let tls =
        crate::key_source::FileKeySource::tls_only(material.cert, tls_key, material.client_ca)?;
    // #59: an optional SECOND token object holds the Ed25519 channel key. When present,
    // `open` builds the delegated handshake signer and the proxy never reads an exported
    // key from disk — a custody the request cannot even state alongside this one.
    Ok(Box::new(crate::pkcs11_keysource::Pkcs11KeySource::open(
        crate::pkcs11_keysource::TokenAccess {
            module_path: token.module,
            pin: pin.expose(),
            token_label: token.token_label,
            key_label: token.key_label,
        },
        tls,
        channel.pkcs11_key_label(),
    )?))
}

/// Default build: the PKCS#11 backend is not compiled, so this FAILS CLOSED here (mirrors
/// the env-keysource gate). The flag still PARSES so the message is precise; no
/// token-backed key is built.
#[cfg(not(feature = "pkcs11_keysource"))]
pub(super) fn open(
    _opening: Opening<'_, '_>,
    _token: Token<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "pkcs11 key source requires the pkcs11_keysource feature (build with \
         --features pkcs11_keysource); not available in this build"
            .to_string(),
    ))
}
