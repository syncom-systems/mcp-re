// SPDX-License-Identifier: Apache-2.0
//! The GCP Cloud KMS key source (ADR-MCPS-028 §C).

use super::Opening;
use crate::key_source::{KeyError, KeySource};

/// The Cloud KMS key version the custody names, and how to reach it.
///
/// Read only by the build that has the backend; the default build refuses before looking.
#[cfg_attr(not(feature = "gcp_kms_keysource"), allow(dead_code))]
pub(super) struct Key<'a> {
    pub(super) key_version: &'a str,
    pub(super) endpoint: Option<&'a str>,
    pub(super) use_metadata: bool,
}

/// Open a source whose signing key is a Cloud KMS key version, with channel material from
/// files.
#[cfg(feature = "gcp_kms_keysource")]
pub(super) fn open(
    opening: Opening<'_, '_>,
    key: Key<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let Opening {
        admitted,
        channel,
        material,
    } = opening;
    let signing = backend(key.key_version, &key)?;
    let tls_key = super::exported_tls_key(admitted, material)?;
    let tls =
        crate::key_source::FileKeySource::tls_only(material.cert, tls_key, material.client_ca)?;
    // #61: the GCP counterpart of #60 — a SECOND, DISTINCT key version custodies the
    // channel key, and the proxy never reads an exported key from disk.
    let Some(channel_key_version) = channel.gcp_key_version() else {
        return Ok(Box::new(crate::kms_keysource::KmsKeySource::new(
            Box::new(signing),
            tls,
        )));
    };
    let channel_signer = backend(channel_key_version, &key)?;
    Ok(Box::new(
        crate::kms_keysource::KmsKeySource::new_with_delegated_tls(
            Box::new(signing),
            tls,
            std::sync::Arc::new(channel_signer),
        )?,
    ))
}

/// One Cloud KMS backend, at the named key version, reached the way `key` says.
#[cfg(feature = "gcp_kms_keysource")]
fn backend(
    key_version: &str,
    key: &Key<'_>,
) -> Result<crate::gcp_kms_keysource::GcpKmsEd25519Backend, KeyError> {
    let config = crate::gcp_kms_keysource::GcpKmsConfig {
        key_version_name: key_version.to_string(),
        endpoint: key.endpoint.map(str::to_string),
    };
    crate::gcp_kms_keysource::GcpKmsEd25519Backend::new(&config, key.use_metadata)
}

/// Default build: the Cloud KMS backend is not compiled, so this FAILS CLOSED here.
#[cfg(not(feature = "gcp_kms_keysource"))]
pub(super) fn open(
    _opening: Opening<'_, '_>,
    _key: Key<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "gcp-kms key source requires the gcp_kms_keysource feature (build with \
         --features gcp_kms_keysource); not available in this build"
            .to_string(),
    ))
}
