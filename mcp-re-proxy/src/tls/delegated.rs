// SPDX-License-Identifier: Apache-2.0
//! The delegated TLS certificate resolver, rendered in the historical error vocabulary.

use std::sync::Arc;

use rustls_pki_types::CertificateDer;

use super::options::TlsError;

/// Produce the delegated TLS certificate resolver for a credential and its signer, in the
/// historical error vocabulary (ADR-MCPS-028 §G, issue #58).
///
/// **Compatibility facade.** It performs no check and makes no decision. Correspondence is
/// a structural precondition of the resolver's existence — [`DelegatedCertResolver::materialize`]
/// establishes it over the very operands it then moves into the resolver — so there is no
/// window here in which the credential and the signer are an unpaired pair, and nothing to
/// delete. All this function does is render a refusal into `TlsError`.
///
/// The budget is supplied by the listener's security state and installed unchanged: it
/// bounds how fast unauthenticated peers can drive a remote, billed, account-throttled
/// signer, and a bucket created per build would be refilled on every reload — bounding a
/// window rather than a rate. That is a listener capability, not a property of the
/// credential, and it is deliberately not part of what correspondence establishes.
pub(crate) fn validated_delegated_resolver(
    server_chain: Vec<CertificateDer<'static>>,
    signer: Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>,
    budget: Arc<crate::delegated_tls::TlsHandshakeSignBudget>,
) -> Result<Arc<crate::delegated_tls::DelegatedCertResolver>, TlsError> {
    crate::delegated_tls::DelegatedCertResolver::materialize(server_chain, signer, budget)
        .map_err(TlsError::DelegatedKeyMismatch)
}

#[cfg(test)]
mod delegated_credential_key_correspondence_tests {
    //! ADR-MCPRE-063 Slice 2 — characterization of the credential/key correspondence
    //! semantics currently bundled into [`validated_delegated_resolver`].
    //!
    //! Written BEFORE the migration and against the unmigrated implementation, which is
    //! the order Slice 1 established: a control written after a migration proves the
    //! migration self-consistent, not the property.
    //!
    //! What these controls pin is that each of the six vectors REFUSES, and which fact
    //! each refusal reports: `TlsError::DelegatedKeyMismatch` carries the authority's
    //! hierarchical refusal, so an empty credential chain and a genuine key mismatch are
    //! distinguishable by matching rather than by reading prose. How a refusal READS is
    //! the algebra's own concern and is controlled at its owner.

    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    use super::*;
    use crate::communication_assurance::credential_key_correspondence::establish_credential_key_correspondence;
    use crate::communication_assurance::credential_key_correspondence::CorrespondenceMismatch;
    use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
    use crate::communication_assurance::credential_public_key_evidence::CredentialKeyRefusal;
    use crate::communication_assurance::ed25519_public_key::Rfc8410SpkiRefusal;
    use crate::communication_assurance::signing_key_evidence::SigningKeyExportEvidence;
    use crate::communication_assurance::signing_key_evidence::SigningKeyRefusal;
    use crate::communication_assurance::CertificateChainEvidence;
    use rcgen::CertificateParams;
    use rcgen::KeyPair;
    use rcgen::PKCS_ED25519;

    /// A delegated signer whose exported public key is whatever the test supplies —
    /// including nothing, which is the "signer yielded no exportable key" vector.
    struct TestSigner {
        exported_spki: Option<Vec<u8>>,
    }

    impl crate::delegated_tls::RawEd25519TlsSigner for TestSigner {
        fn sign_tls_ed25519(
            &self,
            _message: &[u8],
        ) -> Result<Vec<u8>, crate::key_source::KeyError> {
            Ok(vec![0u8; 64])
        }

        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, crate::key_source::KeyError> {
            self.exported_spki.clone().ok_or_else(|| {
                crate::key_source::KeyError::Malformed(
                    "test signer exports no public key".to_string(),
                )
            })
        }
    }

    fn signer(
        exported_spki: Option<Vec<u8>>,
    ) -> Arc<dyn crate::delegated_tls::RawEd25519TlsSigner> {
        Arc::new(TestSigner { exported_spki })
    }

    fn budget() -> Arc<crate::delegated_tls::TlsHandshakeSignBudget> {
        Arc::new(crate::delegated_tls::tests::sized_budget(64, 64))
    }

    /// A self-signed leaf and the SPKI DER of the key it presents.
    fn ed25519_leaf() -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
        let params =
            CertificateParams::new(vec!["delegated.example.org".to_string()]).expect("leaf params");
        let cert = params.self_signed(&key).expect("self-signed leaf");
        let der = cert.der().clone();
        let (_, parsed) = X509Certificate::from_der(der.as_ref()).expect("parse leaf");
        let spki = parsed.public_key().raw.to_vec();
        (der, spki)
    }

    /// A leaf whose public key is a P-256 key: a well-formed SPKI of an algorithm the
    /// delegated path does not support, which is NOT the same as unreadable bytes.
    fn p256_leaf() -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("p256 key");
        let params =
            CertificateParams::new(vec!["delegated.example.org".to_string()]).expect("leaf params");
        params
            .self_signed(&key)
            .expect("self-signed leaf")
            .der()
            .clone()
    }

    #[test]
    fn matching_credential_and_signing_key_is_accepted() {
        let (leaf, spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(spki)), budget()).is_ok(),
            "equal keys under the required profile are the accepting case"
        );
    }

    #[test]
    fn a_signing_key_that_is_not_the_credential_key_is_refused() {
        let (leaf, _) = ed25519_leaf();
        let (_, other_spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(other_spki)), budget()).is_err(),
            "the signer signs for a different key than the credential presents"
        );
    }

    #[test]
    fn an_empty_credential_chain_is_refused() {
        let (_, spki) = ed25519_leaf();
        assert!(validated_delegated_resolver(Vec::new(), signer(Some(spki)), budget()).is_err());
    }

    #[test]
    fn an_unparseable_credential_is_refused() {
        let garbage = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x00]);
        let (_, spki) = ed25519_leaf();
        assert!(validated_delegated_resolver(vec![garbage], signer(Some(spki)), budget()).is_err());
    }

    #[test]
    fn a_credential_whose_key_is_a_supported_shape_of_another_algorithm_is_refused() {
        let (_, spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![p256_leaf()], signer(Some(spki)), budget()).is_err(),
            "a P-256 credential key is well-formed and of the wrong profile"
        );
    }

    #[test]
    fn a_signer_that_exports_no_public_key_is_refused() {
        let (leaf, _) = ed25519_leaf();
        assert!(validated_delegated_resolver(vec![leaf], signer(None), budget()).is_err());
    }

    #[test]
    fn a_signing_key_of_another_algorithm_is_refused() {
        let (leaf, _) = ed25519_leaf();
        // A well-formed P-256 SPKI, taken from a real certificate rather than invented.
        let p256 = p256_leaf();
        let (_, parsed) = X509Certificate::from_der(p256.as_ref()).expect("parse");
        let p256_spki = parsed.public_key().raw.to_vec();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(p256_spki)), budget()).is_err()
        );
    }

    #[test]
    fn a_signing_key_of_another_algorithm_carrying_the_credential_point_is_refused() {
        // The control that actually reaches the required-profile conjunct.
        //
        // Deleting the profile check and comparing the trailing 32 bytes leaves every
        // other negative here GREEN: a P-256 signing key is then refused only because its
        // bytes happen not to match, which is incidental, not enforcement. This vector
        // removes the coincidence — a non-Ed25519 SPKI whose trailing bytes ARE the
        // credential's public point — so the only thing that can refuse it is the profile
        // rule itself. That is the algorithm-confusion shape: a signer of the wrong
        // algorithm accepted as if it were the credential's key.
        let (leaf, spki) = ed25519_leaf();
        let point = &spki[spki.len() - 32..];
        let mut confusable = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x86, 0x48, 0x03, 0x21, 0x00,
        ];
        confusable.extend_from_slice(point);
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(confusable)), budget()).is_err(),
            "an SPKI declaring another algorithm must be refused on the profile rule, even \
             when its trailing bytes are exactly the credential's public point"
        );
    }

    /// One characterized failure: its name, the two sides' evidence, and the refusal it
    /// must be.
    type CharacterizedFailure<'a> = (
        &'a str,
        CertificateChainEvidence<'a>,
        SigningKeyExportEvidence<'a>,
        CredentialKeyCorrespondenceRefusal,
    );

    /// Every case refuses as exactly the fact it states, and no two facts are equal.
    fn assert_each_refusal_is_distinct(cases: Vec<CharacterizedFailure<'_>>) {
        let mut seen = Vec::new();
        for (name, credential, export, expected) in cases {
            let refusal = establish_credential_key_correspondence(credential, export)
                .err()
                .unwrap_or_else(|| panic!("{name} must refuse"));
            assert_eq!(refusal, expected, "{name} reported the wrong fact");
            seen.push(refusal);
        }

        for (i, left) in seen.iter().enumerate() {
            for right in seen.iter().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "every vector must be a DISTINCT value, not a distinct sentence"
                );
            }
        }
    }

    #[test]
    fn every_characterized_failure_is_a_distinct_typed_refusal() {
        // The replacement for the characterization test this suite opened with.
        //
        // Before the slice, every vector arrived as `TlsError::DelegatedKeyMismatch` and
        // was distinguishable ONLY as prose. They are now values of a hierarchical
        // algebra: two sides, each with its own failures, and one mismatch belonging to
        // the relation. The facade still renders a message, because its callers expect
        // one — but the message is a rendering of a fact rather than the only place the
        // fact exists.
        //
        // The property is deliberately count-free. Characterization found six prose-only
        // failures and the algebra already distinguishes more than six, because the key
        // representation alone has three; a later adapter may legitimately add another.
        // What must hold is that every characterized failure is its own value — a name
        // pinning a number would have to be renamed the first time the architecture is
        // right about something new.
        let (leaf, spki) = ed25519_leaf();
        let (_, other_spki) = ed25519_leaf();
        let p256 = p256_leaf();
        let (_, parsed) = X509Certificate::from_der(p256.as_ref()).expect("parse");
        let p256_spki = parsed.public_key().raw.to_vec();
        let garbage = [0x30u8, 0x82, 0xff, 0xff, 0x00];
        let empty: [u8; 0] = [];

        let cases: Vec<CharacterizedFailure<'_>> = vec![
            (
                "empty credential chain",
                CertificateChainEvidence::absent(),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Absent),
            ),
            (
                "unparseable credential",
                CertificateChainEvidence::from_leaf_der(&garbage),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(
                    CredentialKeyRefusal::UninterpretableCredential,
                ),
            ),
            (
                "credential key of another algorithm",
                CertificateChainEvidence::from_leaf_der(p256.as_ref()),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(
                    Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                        oid: "1.2.840.10045.2.1".to_string(),
                    },
                )),
            ),
            (
                "signer exports nothing",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::unavailable(),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Unavailable),
            ),
            (
                "signing key of another algorithm",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&p256_spki),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(
                    Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                        oid: "1.2.840.10045.2.1".to_string(),
                    },
                )),
            ),
            (
                "signer exports unreadable bytes",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&empty),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(
                    Rfc8410SpkiRefusal::Uninterpretable,
                )),
            ),
            (
                "key mismatch",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&other_spki),
                CredentialKeyCorrespondenceRefusal::Mismatch(CorrespondenceMismatch),
            ),
        ];

        assert_each_refusal_is_distinct(cases);
    }

    #[test]
    fn the_accepting_case_yields_the_one_key_both_sides_presented() {
        let (leaf, spki) = ed25519_leaf();
        let facts = establish_credential_key_correspondence(
            CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
            SigningKeyExportEvidence::exported(&spki),
        )
        .expect("equal keys of the required profile");
        assert_eq!(
            facts.corresponding_key().raw_point().as_slice(),
            &spki[spki.len() - 32..],
            "the corresponding key is the key, not a re-derivation of it"
        );
    }
}
