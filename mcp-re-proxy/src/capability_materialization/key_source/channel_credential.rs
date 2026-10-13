// SPDX-License-Identifier: Apache-2.0
//! The channel credential this node serves, established from the materialized key source.
//!
//! Three reads and one relation. The source yields the credential chain, the peer trust
//! anchors and the handshake key, which is DELEGATED xor EXPORTED (ADR-MCPS-028 §G): when the
//! source offers a delegated signer the private key never leaves the device and
//! `tls_server_key()` is never called. The relation is between the custody the deployment
//! REQUESTED for the channel role and the custody those reads ESTABLISHED. Both facts are in
//! hand here and nowhere earlier, so this is where a divergence is refused: a selector that
//! classifies as delegated while the source yields an exported key would otherwise serve
//! handshakes under weaker custody than the deployment declared, and every startup line
//! would report the declared one.
//!
//! # Why possession is the proof
//!
//! [`EstablishedChannelCredential::establish`] is the only producer, and it returns only
//! after the chain read, the anchor read and the key read have all succeeded and the custody
//! comparison agreed. The TLS plane takes this value and nothing else, so a listener cannot
//! be built over a credential whose chain was never read. That read is also what makes
//! `RoleSeparation::NotCompared` safe: a channel role that produced no key fails here, before
//! any server starts.

use rustls_pki_types::CertificateDer;

use crate::config_state::PrivateKeyExposure;
use crate::key_source::{KeyError, KeySource};
use crate::tls_plane::TlsKeyMaterial;

/// The served credential chain, the peer trust anchors and the handshake key, read from one
/// source and known to have the custody the deployment requested.
pub struct EstablishedChannelCredential {
    material: TlsKeyMaterial,
    server_chain: Vec<CertificateDer<'static>>,
    client_ca: Vec<CertificateDer<'static>>,
}

/// What [`EstablishedChannelCredential::into_parts`] hands the TLS plane: the handshake key,
/// the served chain and the peer trust anchors.
pub(crate) type ChannelCredentialParts = (
    TlsKeyMaterial,
    Vec<CertificateDer<'static>>,
    Vec<CertificateDer<'static>>,
);

impl EstablishedChannelCredential {
    /// Read the channel credential from `source`, refusing when the custody it establishes is
    /// not the custody `requested`.
    pub(super) fn establish(
        source: &(dyn KeySource + Send + Sync),
        requested: PrivateKeyExposure,
    ) -> Result<Self, KeyError> {
        let server_chain = source.tls_server_cert_chain()?;
        let client_ca = source.client_ca_roots()?;
        let material = match source.tls_delegated_signer() {
            Some(signer) => TlsKeyMaterial::Delegated(signer),
            None => TlsKeyMaterial::Exported(source.tls_server_key()?),
        };
        let established = material.exposure();
        if established != requested {
            return Err(KeyError::Malformed(format!(
                "TLS custody mismatch: the deployment is configured for {} handshake custody, \
                 but the key source established {} custody. Refusing to serve under a custody \
                 the configuration does not name",
                crate::tls_plane::custody_word(requested),
                crate::tls_plane::custody_word(established),
            )));
        }
        Ok(EstablishedChannelCredential {
            material,
            server_chain,
            client_ca,
        })
    }

    /// The handshake key, the served chain and the peer trust anchors, for the TLS plane that
    /// builds its listener from them.
    ///
    /// `pub(crate)` because that plane lives outside the key-source subtree and is the one
    /// consumer. The custody relation was settled before this value existed, so the parts
    /// carry no invariant a consumer could reassemble wrongly.
    pub(crate) fn into_parts(self) -> ChannelCredentialParts {
        (self.material, self.server_chain, self.client_ca)
    }

    /// A credential assembled from parts, for the TLS plane's own tests, which exercise the
    /// listener build and not the establishment.
    #[cfg(test)]
    pub(crate) fn from_parts_for_tests(
        material: TlsKeyMaterial,
        server_chain: Vec<CertificateDer<'static>>,
        client_ca: Vec<CertificateDer<'static>>,
    ) -> Self {
        EstablishedChannelCredential {
            material,
            server_chain,
            client_ca,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_source::ResponseSigner;
    use mcp_re_core::VerificationKey;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// The delegated signer type the source hands out.
    type DelegatedSigner = std::sync::Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>;

    /// A key source whose channel reads are each set by the test.
    struct ChannelSource {
        /// `None` is a chain the source cannot read.
        chain: Option<Vec<CertificateDer<'static>>>,
        delegated: Option<DelegatedSigner>,
        /// `false` is an exported key the source cannot read.
        exported_key: bool,
        exported_key_reads: std::sync::atomic::AtomicUsize,
    }

    impl ChannelSource {
        fn exported() -> Self {
            ChannelSource {
                chain: Some(Vec::new()),
                delegated: None,
                exported_key: true,
                exported_key_reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn delegated() -> Self {
            let (chain, signer) = crate::delegated_tls::tests::corresponding_material();
            ChannelSource {
                chain: Some(chain),
                delegated: Some(signer),
                ..ChannelSource::exported()
            }
        }
    }

    impl ResponseSigner for ChannelSource {
        fn sign_response(&self, _preimage: &[u8]) -> Result<String, KeyError> {
            Err(KeyError::NotFound("no response key in this fixture".into()))
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Err(KeyError::NotFound("no response key in this fixture".into()))
        }
    }

    impl KeySource for ChannelSource {
        fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
            self.chain
                .clone()
                .ok_or_else(|| KeyError::NotFound("tls.crt".into()))
        }
        fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
            self.exported_key_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if !self.exported_key {
                return Err(KeyError::NotFound("tls.key".into()));
            }
            let key = rcgen::KeyPair::generate().expect("key");
            Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )))
        }
        fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
            Ok(Vec::new())
        }
        fn tls_delegated_signer(&self) -> Option<DelegatedSigner> {
            self.delegated.clone()
        }
    }

    /// A deployment configured for delegated handshake custody must not be served by an
    /// exported key.
    #[test]
    fn an_exported_key_under_requested_delegated_custody_refuses() {
        let refusal = EstablishedChannelCredential::establish(
            &ChannelSource::exported(),
            PrivateKeyExposure::NonExporting,
        )
        .err()
        .expect("mismatched custody must refuse");
        let refusal = refusal.to_string();
        assert!(refusal.contains("custody mismatch"), "{refusal}");
        assert!(
            refusal.contains("delegated") && refusal.contains("exported-key"),
            "the refusal must name both sides: {refusal}"
        );
    }

    /// The other direction: a device signer where the deployment declared an exported key.
    #[test]
    fn a_delegated_signer_under_requested_exported_custody_refuses() {
        let refusal = EstablishedChannelCredential::establish(
            &ChannelSource::delegated(),
            PrivateKeyExposure::ProcessReadable,
        )
        .err()
        .expect("mismatched custody must refuse");
        assert!(
            refusal.to_string().contains("custody mismatch"),
            "{refusal}"
        );
    }

    /// Negative control: agreement is not refused, in either custody. Without this the two
    /// refusals above would pass just as well if `establish` refused everything.
    #[test]
    fn agreeing_custody_establishes_the_credential() {
        let exported = EstablishedChannelCredential::establish(
            &ChannelSource::exported(),
            PrivateKeyExposure::ProcessReadable,
        )
        .expect("agreeing exported custody establishes");
        assert!(matches!(exported.material, TlsKeyMaterial::Exported(_)));

        let delegated = EstablishedChannelCredential::establish(
            &ChannelSource::delegated(),
            PrivateKeyExposure::NonExporting,
        )
        .expect("agreeing delegated custody establishes");
        assert!(matches!(delegated.material, TlsKeyMaterial::Delegated(_)));
    }

    /// Under delegated custody the exported key is never read, so a device that cannot
    /// export it is not asked to.
    #[test]
    fn a_delegated_signer_is_used_without_reading_an_exported_key() {
        let source = ChannelSource {
            exported_key: false,
            ..ChannelSource::delegated()
        };
        EstablishedChannelCredential::establish(&source, PrivateKeyExposure::NonExporting)
            .expect("the delegated path does not consult the exported key");
        assert_eq!(
            source
                .exported_key_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// A chain that cannot be read refuses establishment. This is the read that keeps a
    /// channel role that produced no key from reaching a listener.
    #[test]
    fn an_unreadable_channel_chain_refuses_establishment() {
        let source = ChannelSource {
            chain: None,
            ..ChannelSource::exported()
        };
        let refusal =
            EstablishedChannelCredential::establish(&source, PrivateKeyExposure::ProcessReadable)
                .err()
                .expect("an unreadable chain must refuse");
        assert!(refusal.to_string().contains("tls.crt"), "{refusal}");
    }

    /// An exported key that cannot be read refuses establishment rather than producing a
    /// credential without a key.
    #[test]
    fn an_unreadable_exported_key_refuses_establishment() {
        let source = ChannelSource {
            exported_key: false,
            ..ChannelSource::exported()
        };
        assert!(EstablishedChannelCredential::establish(
            &source,
            PrivateKeyExposure::ProcessReadable
        )
        .is_err());
    }
}
