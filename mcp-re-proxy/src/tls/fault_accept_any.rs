// SPDX-License-Identifier: Apache-2.0
//! MCPS-079 fault-injection module ("test of the tests"), the symmetric mirror of
//! mcp-re-transport's `fault_accept_any` (server-side). Compiled ONLY under the
//! `fault_accept_any_client` feature, which is off by default and never enabled by
//! production targets or the default `bazel test //...`. It re-introduces the
//! `AcceptAnyClient` anti-pattern the verifying proxy was built to eliminate, so
//! the periodic fault-injection harness can prove the proxy's client-cert
//! rejection guards (the more important boundary — the proxy guards the inner)
//! would FAIL if the control were broken.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls::crypto::CryptoProvider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::danger::ClientCertVerified;
use rustls::server::danger::ClientCertVerifier;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::Error as RustlsError;
use rustls::SignatureScheme;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::UnixTime;

/// A client-certificate verifier that accepts ANY client certificate: any CA,
/// any identity, any validity window — and, via the `client_auth_mandatory`
/// override, also accepts a connection that presents NO client certificate at
/// all. Handshake SIGNATURES are still checked via the crypto provider (so the
/// TLS handshake completes against a real client) — only the trust/identity/
/// expiry decision is neutered. This is the exact shape of the control break
/// the proxy's client-auth tests exist to catch.
#[derive(Debug)]
pub struct AcceptAnyClientVerifier {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyClientVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        AcceptAnyClientVerifier { provider }
    }

    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.provider.signature_verification_algorithms
    }
}

impl ClientCertVerifier for AcceptAnyClientVerifier {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // THE BREAK: trust, identity, and expiry are never checked.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No trust anchors are advertised — the faulted verifier ignores trust
        // entirely, so there are no issuer hints to send to the client.
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        // THE SECOND BREAK: a client certificate is no longer required. This is
        // what flips T1 (`missing_client_certificate_is_rejected`): with this
        // returning `false`, a connection presenting NO client cert completes
        // the handshake instead of being rejected. T2
        // (`untrusted_client_certificate_is_rejected`) flips via
        // `verify_client_cert` above accepting any presented cert.
        false
    }
}
