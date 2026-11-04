// SPDX-License-Identifier: Apache-2.0
//! The TLS an outbound agent speaks.
//!
//! One fact: **an HTTPS destination is authenticated against the public Web PKI roots the
//! `webpki-roots` 1.x crate ships, by rustls on the *ring* provider, presenting no client
//! certificate.** ureq is built without any TLS feature, so the connector that speaks TLS is
//! this one, installed by [`VettedDestination::agent`](super::VettedDestination::agent) after
//! ureq's own TCP connector. Owning it here names the root set this proxy trusts on the wire.
//!
//! An agent built without this connector refuses every `https` URL (ureq reports
//! `TlsRequired`), so a destination whose agent did not come from `VettedDestination::agent`
//! cannot speak TLS under some other root set by omission.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::{Arc, OnceLock};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, Transport,
    TransportAdapter,
};

/// A rustls connector over one root set.
#[derive(Clone)]
pub(super) struct RootedConnector {
    /// `None` when the provider offers no safe protocol version; every HTTPS connection is
    /// then refused rather than attempted under weaker terms.
    config: Option<Arc<ClientConfig>>,
}

impl RootedConnector {
    /// The connector every outbound agent installs: the public Web PKI roots, built once.
    pub(super) fn public() -> Self {
        static PUBLIC: OnceLock<RootedConnector> = OnceLock::new();
        PUBLIC.get_or_init(|| Self::over(public_roots())).clone()
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
    fn handshake<S: Read + Write>(
        &self,
        dns_name: &str,
        mut io: S,
    ) -> io::Result<StreamOwned<ClientConnection, S>> {
        let config = self
            .config
            .clone()
            .ok_or_else(|| io::Error::other("no safe TLS protocol version is available"))?;
        // A URL carries an IPv6 literal in brackets; a TLS server name never has them.
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

impl fmt::Debug for RootedConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootedConnector").finish_non_exhaustive()
    }
}

/// The TLS stage of an agent's connector chain: an `https` URL over a transport that is not
/// already TLS is wrapped in a session authenticated by this connector; anything else passes
/// through unchanged.
impl Connector<Box<dyn Transport>> for RootedConnector {
    type Out = Either<Box<dyn Transport>, TlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<Box<dyn Transport>>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let host = details
            .uri
            .host()
            .ok_or(ureq::Error::Tls("an https URL without a host"))?;
        let mut io = TransportAdapter::new(transport, Arc::clone(&details.current_time));
        io.set_timeout(details.timeout);
        let stream = self.handshake(host, io)?;
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        Ok(Some(Either::B(TlsTransport { buffers, stream })))
    }
}

/// The public Web PKI root set, whole, as `webpki-roots` ships it.
fn public_roots() -> RootCertStore {
    let roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    RootCertStore { roots }
}

/// An established session over the agent's transport.
pub(super) struct TlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl Transport for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let output = self.buffers.output().get(..amount).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output beyond the buffer")
        })?;
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.sock.get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

impl fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTransport").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::net::{TcpListener, TcpStream};

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    use super::*;

    /// A CA outside every public root set, and a `localhost` leaf it signed.
    pub(in crate::outbound_fetch) fn private_pki() -> (
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
    pub(in crate::outbound_fetch) fn serve(
        leaf: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> u16 {
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

    fn dial(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).expect("connect")
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

    /// ureq on its own speaks no TLS, so this connector is the only TLS an outbound agent has.
    ///
    /// An agent over ureq's default connector chain alone refuses an `https` URL as
    /// `TlsRequired`. `RootedConnector` passes an already-TLS transport through, so were ureq
    /// ever built with a TLS feature — a dependency enabling one through feature unification —
    /// ureq's TLS would authenticate the server under its own roots and this connector would
    /// never run. That agent would then attempt a handshake here and fail some other way.
    #[test]
    fn ureq_alone_speaks_no_tls() {
        use ureq::unversioned::resolver::DefaultResolver;
        use ureq::unversioned::transport::DefaultConnector;

        let (_ca, leaf, key) = private_pki();
        let port = serve(leaf, key);
        let config = ureq::Agent::config_builder().proxy(None).build();
        let agent =
            ureq::Agent::with_parts(config, DefaultConnector::new(), DefaultResolver::default());
        let refused = agent
            .get(format!("https://localhost:{port}/"))
            .call()
            .expect_err("ureq alone has no TLS to speak");
        assert!(
            matches!(refused, ureq::Error::TlsRequired),
            "ureq handled https itself: {refused:?}"
        );
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
