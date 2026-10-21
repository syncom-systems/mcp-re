// SPDX-License-Identifier: Apache-2.0
//! The TLS an outbound agent speaks.
//!
//! One fact: **an HTTPS destination is authenticated against the public Web PKI roots the
//! `webpki-roots` 1.x crate ships, by rustls on the *ring* provider, presenting no client
//! certificate.** That is the configuration ureq's own `tls` feature installed, but ureq 2
//! reaches those roots only through the `webpki-roots` 0.26 compatibility shim. Owning the
//! connector here names the root set this proxy trusts on the wire and keeps the shim out of
//! the build graph.
//!
//! An agent built without a connector refuses every `https` URL, so a destination whose
//! agent did not come from [`VettedDestination::agent`](super::VettedDestination::agent)
//! cannot speak TLS under some other root set by omission.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use ureq::ReadWrite;

/// A rustls connector over one root set.
pub(super) struct RootedConnector {
    /// `None` when the provider offers no safe protocol version; every HTTPS connection is
    /// then refused rather than attempted under weaker terms.
    config: Option<Arc<ClientConfig>>,
}

impl RootedConnector {
    /// The connector every outbound agent installs: the public Web PKI roots, built once.
    pub(super) fn public() -> Arc<Self> {
        static PUBLIC: OnceLock<Arc<RootedConnector>> = OnceLock::new();
        Arc::clone(PUBLIC.get_or_init(|| Arc::new(Self::over(public_roots()))))
    }

    fn over(roots: RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()
            .map(|versions| Arc::new(versions.with_root_certificates(roots).with_no_client_auth()));
        Self { config }
    }

    /// Complete the handshake over `io` for `dns_name`, or say why it did not complete.
    fn handshake(
        &self,
        dns_name: &str,
        mut io: Box<dyn ReadWrite>,
    ) -> io::Result<StreamOwned<ClientConnection, Box<dyn ReadWrite>>> {
        let config = self
            .config
            .clone()
            .ok_or_else(|| io::Error::other("no safe TLS protocol version is available"))?;
        // ureq hands over an IPv6 literal in brackets; a TLS server name never has them.
        let host = dns_name
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(dns_name);
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a TLS server name"))?;
        let mut session = ClientConnection::new(config, name).map_err(io::Error::other)?;
        session.complete_io(&mut io)?;
        Ok(StreamOwned::new(session, io))
    }
}

impl ureq::TlsConnector for RootedConnector {
    fn connect(
        &self,
        dns_name: &str,
        io: Box<dyn ReadWrite>,
    ) -> Result<Box<dyn ReadWrite>, ureq::Error> {
        let stream = self.handshake(dns_name, io)?;
        Ok(Box::new(TlsStream(stream)))
    }
}

/// The public Web PKI root set, whole, as `webpki-roots` ships it.
fn public_roots() -> RootCertStore {
    let roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    RootCertStore { roots }
}

/// An established session over the agent's transport.
struct TlsStream(StreamOwned<ClientConnection, Box<dyn ReadWrite>>);

impl ReadWrite for TlsStream {
    fn socket(&self) -> Option<&TcpStream> {
        self.0.get_ref().socket()
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TlsStream").finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    use super::*;

    /// A CA outside every public root set, and a `localhost` leaf it signed.
    fn private_pki() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca = CertificateParams::new(Vec::new()).expect("ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca.distinguished_name
            .push(DnType::CommonName, "private-test-ca");
        let ca_cert = ca.self_signed(&ca_key).expect("ca self-signed");
        let issuer = rcgen::Issuer::from_params(&ca, &ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::new(Vec::new()).expect("leaf params");
        leaf.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("san"))];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf signed");
        (
            ca_cert.der().clone(),
            leaf_cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
    }

    /// A loopback TLS server presenting `leaf`, answering one `ping` with `pong`.
    fn serve(leaf: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("server cert");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            let session = ServerConnection::new(Arc::new(config)).expect("server session");
            let mut stream = StreamOwned::new(session, tcp);
            let mut ping = [0_u8; 4];
            if stream.read_exact(&mut ping).is_ok() && &ping == b"ping" {
                let _ = stream.write_all(b"pong");
                let _ = stream.flush();
            }
        });
        port
    }

    fn dial(port: u16) -> Box<dyn ReadWrite> {
        Box::new(TcpStream::connect(("127.0.0.1", port)).expect("connect"))
    }

    /// The mirror of the refusal below: the same server, under a root set that holds its CA,
    /// completes the handshake and carries bytes. Without it the refusal is satisfied by a
    /// connector that refuses everything.
    #[test]
    fn a_server_under_a_trusted_root_completes_the_handshake_and_carries_bytes() {
        let (ca, leaf, key) = private_pki();
        let port = serve(leaf, key);
        let mut roots = RootCertStore::empty();
        roots.add(ca).expect("anchor");
        let mut stream = RootedConnector::over(roots)
            .handshake("localhost", dial(port))
            .expect("a server under a trusted root is accepted");
        stream.write_all(b"ping").expect("write");
        let mut pong = [0_u8; 4];
        stream.read_exact(&mut pong).expect("read");
        assert_eq!(&pong, b"pong");
    }

    /// The connector every outbound agent installs authenticates the server: a certificate
    /// chaining to no public root is refused as an unknown issuer, before any request byte.
    #[test]
    fn the_public_connector_refuses_a_server_outside_the_public_roots() {
        let (_ca, leaf, key) = private_pki();
        let port = serve(leaf, key);
        let refused = RootedConnector::public()
            .handshake("localhost", dial(port))
            .expect_err("a private CA is not a public root");
        let cause = refused
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>());
        assert_eq!(
            cause,
            Some(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )),
            "refused for the wrong reason: {refused}"
        );
    }

    /// The public connector is built over the whole shipped root set, not an empty store
    /// that would refuse every server for a reason unrelated to who issued it.
    #[test]
    fn the_public_connector_is_built_over_the_shipped_root_set() {
        assert!(webpki_roots::TLS_SERVER_ROOTS.len() > 100);
        assert_eq!(public_roots().len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(RootedConnector::public().config.is_some());
    }

    /// A name a TLS server cannot carry is refused before the handshake begins.
    #[test]
    fn a_name_that_is_not_a_server_name_is_refused() {
        let (_ca, leaf, key) = private_pki();
        let port = serve(leaf, key);
        let refused = RootedConnector::public()
            .handshake("not a host name", dial(port))
            .expect_err("refused");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    }
}
