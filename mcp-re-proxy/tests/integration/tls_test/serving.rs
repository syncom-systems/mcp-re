//! The mTLS round trip: server configurations, the client that dials them, and the
//! one-connection server thread.

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use mcp_re_proxy::communication_assurance::AuthenticatedChannelPeer;
use mcp_re_proxy::serve_once;
use mcp_re_proxy::tls_listener_state::TlsListenerSecurityState;
use mcp_re_proxy::ServerOptions;

use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;

use super::pki::dns;
use super::pki::make_ca;
use super::pki::make_leaf;
use super::pki::uri;
use super::pki::window;
use super::pki::Ca;

/// The client credential presented in the handshake: its chain and private key.
pub(super) type ClientCredential = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// The identity every happy-path client certificate carries as its URI SAN.
pub(super) const AGENT_1: &str = "spiffe://example.org/agent-1";

/// The request body every happy-path round trip sends.
pub(super) const JSONRPC_BODY: &[u8] = b"{\"jsonrpc\":\"2.0\"}";

/// The response body every happy-path inner handler returns.
pub(super) const OK_BODY: &[u8] = b"{\"ok\":true}";

/// A client config that FULLY validates the server: rustls's stock WebPKI server
/// verifier anchored at `server_root` performs real chain building, validity,
/// hostname (SAN), AND `CertificateVerify` signature verification — nothing is
/// asserted. A handshake completes only if the server cert chains to `server_root`,
/// matches `localhost`, AND the signature over the transcript is cryptographically
/// valid; the delegated-TLS tests rely on this so a bogus delegated signature (or an
/// untrusted/mismatched cert) FAILS the handshake.
pub(super) fn client_config(
    server_root: &CertificateDer<'static>,
    client_auth: Option<ClientCredential>,
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server_root.clone()).expect("add server CA root");
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots);
    match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client auth cert"),
        None => builder.with_no_client_auth(),
    }
}

/// Connect as a TLS client, send one HTTP POST with `body`, return the response
/// body. Returns Err if the TLS handshake or IO fails (e.g. rejected client cert).
pub(super) fn client_round_trip(
    addr: SocketAddr,
    config: ClientConfig,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut response = Vec::new();
    // A peer that closes without close_notify surfaces as UnexpectedEof; tolerate
    // it and use what was read.
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    // Return the body (after the header terminator).
    let split = b"\r\n\r\n";
    let pos = response
        .windows(split.len())
        .position(|w| w == split)
        .map(|p| p + split.len())
        .unwrap_or(0);
    Ok(response[pos..].to_vec())
}

/// Dial `addr`, validating the server against `server_root`, presenting `client`.
pub(super) fn dial(
    addr: SocketAddr,
    server_root: &CertificateDer<'static>,
    client: Option<ClientCredential>,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    client_round_trip(addr, client_config(server_root, client), body)
}

/// The server configuration trusting `client_cas` for client auth, with offline CRL
/// revocation over `crls` (#3839; the verifier denies unknown status, failing closed),
/// plus the DER of the CA that issued its leaf, which clients anchor their server
/// verification at.
pub(super) fn server_config_trusting(
    client_cas: &[&Ca],
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let server_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let config = TlsListenerSecurityState::new(
        client_cas.iter().map(|ca| ca.der()).collect(),
        mcp_re_proxy::delegated_tls::HandshakeSignCapacity::default(),
    )
    .build_exported_key_config(vec![server_cert], server_key, crls)
    .expect("server config");
    (Arc::new(config), server_ca.der())
}

/// The server configuration for `ca`'s client certificates, without revocation.
pub(super) fn server_config_for(ca: &Ca) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    server_config_trusting(&[ca], Vec::new())
}

/// The server options every served test deployment states.
fn server_options() -> ServerOptions {
    ServerOptions::new(
        window(),
        mcp_re_proxy::config_state::RequestTarget::new("https://localhost/")
            .expect("an absolute target"),
    )
}

/// What a one-connection server thread returns: the verified client identity, if any.
pub(super) type ServedPeer = std::io::Result<Option<AuthenticatedChannelPeer>>;

/// Serve exactly one connection on a fresh loopback port with `config`, answering with
/// `inner`. Returns the address to dial and the thread to join for the outcome.
pub(super) fn spawn_server<H>(
    config: Arc<rustls::ServerConfig>,
    inner: H,
) -> (SocketAddr, JoinHandle<ServedPeer>)
where
    H: FnOnce(&[u8], Option<AuthenticatedChannelPeer>) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || serve_once(&listener, config, &server_options(), inner));
    (addr, server)
}

/// Serve one connection whose inner handler answers [`OK_BODY`] to any request.
pub(super) fn spawn_ok_server(
    config: Arc<rustls::ServerConfig>,
) -> (SocketAddr, JoinHandle<ServedPeer>) {
    spawn_server(config, |_request, _identity| OK_BODY.to_vec())
}

/// An inner handler that checks it was handed [`JSONRPC_BODY`] and answers [`OK_BODY`].
pub(super) fn expect_jsonrpc_answer_ok(
    request: &[u8],
    _identity: Option<AuthenticatedChannelPeer>,
) -> Vec<u8> {
    assert_eq!(request, JSONRPC_BODY);
    OK_BODY.to_vec()
}

/// A currently-valid client credential for [`AGENT_1`] issued by `ca`.
pub(super) fn agent_credential(ca: &Ca) -> ClientCredential {
    let (cert, key) = make_leaf(ca, vec![uri(AGENT_1)], None, true);
    (vec![cert], key)
}

/// The delegated-TLS server configuration for `server_cert`, signed by `signer` and
/// trusting `client_ca` for client auth, built through the owner's validating path.
pub(super) fn delegated_config<S>(
    client_ca: &Ca,
    server_cert: CertificateDer<'static>,
    signer: S,
) -> Result<rustls::ServerConfig, mcp_re_proxy::TlsError>
where
    S: mcp_re_proxy::RawEd25519TlsSigner + 'static,
{
    TlsListenerSecurityState::new(
        vec![client_ca.der()],
        mcp_re_proxy::delegated_tls::HandshakeSignCapacity::default(),
    )
    .build_delegated_config(vec![server_cert], Arc::new(signer), Vec::new())
}
