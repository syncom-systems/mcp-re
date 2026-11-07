// SPDX-License-Identifier: Apache-2.0
//! The harness's TLS client: mTLS config, HTTP/1.1 round trips, signed requests and the response checks.

use super::*;

// --- TLS client ---------------------------------------------------------------

/// Build the client mTLS config ONCE (the trusted URI-SAN leaf carrying the RFC 9421
/// actor_id) and share it via `Arc` across every connection, so the measured latency
/// is the handshake + request cost, not repeated config/cert construction.
pub(super) fn build_client_config(
    ca: &Ca,
    server_root: &CertificateDer<'static>,
) -> Arc<ClientConfig> {
    let (leaf, key) = make_client_leaf(ca, vec![uri(CLIENT_SUBJECT)]);
    client_config_from(&leaf, &key, server_root)
}

/// A client mTLS config presenting `leaf`+`key` — shared by the short-lived
/// (accepted) leaf and, in the in-process serve test, a long-lived leaf that the
/// proxy's cert-lifetime ceiling must reject.
pub(super) fn client_config_from(
    leaf: &rcgen::Certificate,
    key: &KeyPair,
    server_root: &CertificateDer<'static>,
) -> Arc<ClientConfig> {
    let chain = vec![leaf.der().clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut roots = RootCertStore::empty();
    roots.add(server_root.clone()).expect("add server CA root");
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key_der)
        .expect("client auth");
    Arc::new(config)
}

/// One HTTP reply off the wire: status line + parsed headers + body.
pub(super) struct HttpReply {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
    keeps_alive: bool,
}

/// The header block of one HTTP/1.1 response, read off `stream` up to `\r\n\r\n`.
fn read_header_block(stream: &mut impl Read) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before response headers completed",
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
}

/// The status code of an `HTTP/1.1 <code> <reason>` line.
fn parse_status(status_line: &str) -> std::io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no HTTP status in response",
            )
        })
}

/// The `Name: value` lines of a header block, in original case (needed for RFC 9421
/// response-signature verification).
fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn content_length(headers: &[(String, String)]) -> std::io::Result<usize> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no Content-Length in response",
            )
        })
}

/// Read one HTTP/1.1 response off `stream`: consume the header block up to
/// `\r\n\r\n`, parse the status line + headers (original case, needed for RFC 9421
/// response-signature verification) + `Content-Length`, then read exactly that many
/// body bytes. `keeps_alive` is false when the response carried `Connection: close`
/// (the current proxy always does).
fn read_http_response(stream: &mut impl Read) -> std::io::Result<HttpReply> {
    let header_text = read_header_block(stream)?;
    let mut lines = header_text.lines();
    // "HTTP/1.1 <code> <reason>"
    let status = parse_status(lines.next().unwrap_or_default())?;
    let headers = parse_headers(lines);
    let content_length = content_length(&headers)?;
    let keeps_alive = !headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));

    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;
    Ok(HttpReply {
        status,
        headers,
        body,
        keeps_alive,
    })
}

/// Serialize the request line + signed headers + transport headers for a POST.
fn http_post_head(
    signed_headers: &[(String, String)],
    keep_alive: bool,
    body_len: usize,
) -> String {
    let mut head = String::from("POST / HTTP/1.1\r\nHost: localhost\r\n");
    for (k, v) in signed_headers {
        // Content-Length / Connection are transport-owned below; the signed set
        // never carries them, but guard against accidental duplication.
        if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("connection") {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let conn = if keep_alive { "keep-alive" } else { "close" };
    head.push_str(&format!(
        "Content-Length: {body_len}\r\nConnection: {conn}\r\n\r\n"
    ));
    head
}

/// Open a fresh mTLS connection, send one RFC 9421-signed request (signature in
/// headers), and read the response (cold-handshake path).
pub(super) fn cold_round_trip(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    signed: &SignedRequest,
) -> std::io::Result<HttpReply> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(config, server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let req = signed.request();
    let head = http_post_head(&req.headers, false, req.body.len());
    stream.write_all(head.as_bytes())?;
    stream.write_all(&req.body)?;
    stream.flush()?;
    read_http_response(&mut stream)
}

// --- signed requests (real clock) ---------------------------------------------

pub(super) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What every signed request shares: a UNIQUE `nonce` (each request draws a fresh 128-bit
/// one, the emission floor the client core enforces) so replay never fires across the load
/// run, the real clock, the audience, and the DPoP binding.
fn signing_inputs() -> RequestSigningInputs {
    let nonce = &mcp_re_test_paths::unique_test_nonce();
    let now = now_unix();
    let audience = AudienceTuple {
        audience_id: AUDIENCE.to_string(),
        target_uri: TARGET_URI.to_string(),
        route: None,
    };
    let binding = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, DPOP_TOKEN.as_bytes());
    RequestSigningInputs::new(
        SIGNER_A_KEY_ID,
        audience,
        vec![binding],
        nonce,
        now,
        now + 300,
    )
    .with_headers(vec![(
        "Authorization".to_string(),
        format!("Bearer {DPOP_TOKEN}"),
    )])
}

/// Sign a `tools/call`-shaped `echo` request as the request signer, timestamped at
/// the real clock and carrying a UNIQUE `nonce` so replay never fires across the
/// load run. RFC 9421 + RFC 9530 via the audited `mcp-re-client-core` — the
/// signature rides in the returned request's HTTP headers, not a body object.
pub(super) fn signed_request() -> SignedRequest {
    let inputs = signing_inputs();
    let mut params = Map::new();
    params.insert("text".to_string(), Value::String("hello".to_string()));
    build_signed_message(
        McpMessage::new(Some(&Value::String("req-1".to_string())), "echo", params),
        TARGET_URI,
        &inputs,
        &signer_a_key(),
    )
    .expect("client signs RFC 9421 request")
}

/// The same request, carrying a PDP authorization decision the client binds into the
/// signature — the SDK path (`with_authorization_decision`), not a hand-built block.
pub(super) fn signed_request_with_decision(decision: &str) -> SignedRequest {
    let inputs = signing_inputs().with_authorization_decision(decision);
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(DECIDED_TOOL.to_string()));
    params.insert("arguments".to_string(), json!({ "text": "hello" }));
    build_signed_message(
        McpMessage::new(Some(&Value::String("req-1".to_string())), "tools/call", params),
        TARGET_URI,
        &inputs,
        &signer_a_key(),
    )
    .expect("client signs RFC 9421 request with a carried decision")
}

/// The server actor resolver for verifying the signed response (Response slot).
pub(super) fn server_resolve(kid: &str, slot: SignerSlot) -> Option<ResolvedActor> {
    if slot == SignerSlot::Response && kid == SERVER_KEY_ID {
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: "server".to_string(),
                trust_domain: TRUST_DOMAIN.to_string(),
                subject: SERVER.to_string(),
                keyid: SERVER_KEY_ID.to_string(),
            },
            verification_key: server_verification_key(),
            slot,
        })
    } else {
        None
    }
}

fn server_verification_key() -> VerificationKey {
    SigningKey::from_seed_bytes(&server_seed()).public_key()
}

/// A response is a SUCCESS iff it parses as a JSON object with no `error` and a
/// `result` — the proxy fails closed with a JSON-RPC error object, so "no error +
/// result" means the inner result was signed and returned.
pub(super) fn is_success(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .map(|v| v.get("error").is_none() && v.get("result").is_some())
        .unwrap_or(false)
}

/// One keep-alive connection, reused across requests.
pub(super) struct KeepAliveClient {
    pub(super) stream: Option<StreamOwned<ClientConnection, TcpStream>>,
    pub(super) reconnects: Arc<AtomicUsize>,
}

impl KeepAliveClient {
    pub(super) fn new(reconnects: Arc<AtomicUsize>) -> Self {
        KeepAliveClient {
            stream: None,
            reconnects,
        }
    }

    /// Keep-alive round-trip: reuse the stream if present, else open a new connection
    /// (counting it as a reconnect once the first request has been served). Drops the
    /// stream when the server signals `Connection: close`.
    pub(super) fn round_trip(
        &mut self,
        addr: SocketAddr,
        config: Arc<ClientConfig>,
        signed: &SignedRequest,
    ) -> std::io::Result<HttpReply> {
        if self.stream.is_none() {
            let tcp = TcpStream::connect(addr)?;
            let server_name = ServerName::try_from("localhost").expect("server name");
            let conn = ClientConnection::new(config, server_name)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            self.stream = Some(StreamOwned::new(conn, tcp));
        }
        let stream = self.stream.as_mut().expect("stream present");

        let req = signed.request();
        let head = http_post_head(&req.headers, true, req.body.len());
        stream.write_all(head.as_bytes())?;
        stream.write_all(&req.body)?;
        stream.flush()?;
        let reply = read_http_response(stream)?;
        if !reply.keeps_alive {
            self.stream = None;
            self.reconnects.fetch_add(1, Ordering::Relaxed);
        }
        Ok(reply)
    }
}
