// SPDX-License-Identifier: Apache-2.0
//! The connection workers: each is a tokio task that replays the corpus over its own
//! TLS connection and keeps its counts in the shared tallies.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::args::Args;
use super::response::read_response;

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// What the workers share: the corpus they replay and the tallies they report into.
pub(super) struct Shared {
    corpus: Vec<Vec<u8>>,
    config: Arc<ClientConfig>,
    target: String,
    keep_alive: bool,
    next: AtomicUsize,
    ok: AtomicUsize,
    failed: AtomicUsize,
    handshakes: AtomicU64,
    latencies: Mutex<Vec<u64>>,
    /// First failure reason, kept verbatim. A rig that reports "8000 failures" without
    /// saying why costs more time than the line that records it.
    first_err: Mutex<Option<String>>,
}

/// The measured window, as absolute wall clock plus its own duration.
pub(super) struct Window {
    pub(super) start_ms: u64,
    pub(super) end_ms: u64,
    pub(super) elapsed_secs: f64,
}

/// What the workers counted.
pub(super) struct Totals {
    pub(super) successes: usize,
    pub(super) failures: usize,
    pub(super) handshakes: u64,
    /// Sorted ascending.
    pub(super) latencies_us: Vec<u64>,
    pub(super) first_error: Option<String>,
}

impl Shared {
    pub(super) fn new(a: &Args, corpus: Vec<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            corpus,
            config: client_config(a),
            target: a.target.clone(),
            keep_alive: a.keep_alive(),
            next: AtomicUsize::new(0),
            ok: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            handshakes: AtomicU64::new(0),
            latencies: Mutex::new(Vec::with_capacity(a.requests)),
            first_err: Mutex::new(None),
        })
    }

    fn note(&self, msg: String) {
        let mut g = self.first_err.lock().expect("first_err");
        if g.is_none() {
            *g = Some(msg);
        }
    }

    fn fail(&self, msg: String) {
        self.note(msg);
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn totals(&self) -> Totals {
        let mut latencies_us = self.latencies.lock().expect("lat").clone();
        latencies_us.sort_unstable();
        Totals {
            successes: self.ok.load(Ordering::Relaxed),
            failures: self.failed.load(Ordering::Relaxed),
            handshakes: self.handshakes.load(Ordering::Relaxed),
            latencies_us,
            first_error: self.first_err.lock().expect("first_err").clone(),
        }
    }
}

/// The TLS client identity and the trust root the server is verified against.
fn client_config(a: &Args) -> Arc<ClientConfig> {
    // DER, not PEM: the orchestrator writes what rustls consumes directly, so the
    // generator needs no PEM parser and the rig gains no dependency.
    let chain = vec![CertificateDer::from(
        std::fs::read(&a.client_cert).expect("client cert der"),
    )];
    let key_der = PrivateKeyDer::try_from(std::fs::read(&a.client_key).expect("client key der"))
        .expect("client key is PKCS#8 DER");

    // The server is verified against the CA that issued its leaf (DER, like the client
    // material): chain, validity, `localhost` SAN and handshake signature are all checked.
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            std::fs::read(&a.server_ca).expect("server ca der"),
        ))
        .expect("add server CA root");

    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key_der)
            .expect("client auth"),
    )
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

/// Replay the corpus over `connections` workers and report the window it took.
///
/// The window is absolute wall clock, so the orchestrator can compute TRUE aggregate
/// throughput over the union of the generators' windows. Summing each generator's own
/// successes/elapsed overstates the total whenever their windows are staggered — and
/// they are, because each pre-signs its corpus first.
pub(super) fn drive(shared: &Arc<Shared>, connections: usize) -> Window {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let start_ms = wall_clock_ms();
    let started = Instant::now();
    rt.block_on(async {
        let tasks: Vec<_> = (0..connections)
            .map(|_| tokio::spawn(Worker::new(Arc::clone(shared)).run()))
            .collect();
        for t in tasks {
            let _ = t.await;
        }
    });
    Window {
        start_ms,
        end_ms: wall_clock_ms(),
        elapsed_secs: started.elapsed().as_secs_f64(),
    }
}

/// One connection's loop: claim the next corpus entry, send it, read the verdict.
struct Worker {
    shared: Arc<Shared>,
    connector: tokio_rustls::TlsConnector,
    held: Option<TlsStream>,
    local: Vec<u64>,
    buf: Vec<u8>,
}

impl Worker {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            connector: tokio_rustls::TlsConnector::from(Arc::clone(&shared.config)),
            shared,
            held: None,
            local: Vec::new(),
            buf: Vec::with_capacity(16 * 1024),
        }
    }

    async fn run(mut self) {
        let shared = Arc::clone(&self.shared);
        loop {
            let i = shared.next.fetch_add(1, Ordering::Relaxed);
            if i >= shared.corpus.len() {
                break;
            }
            let t0 = Instant::now();
            let outcome = self.exchange(i).await;
            self.settle(outcome, t0);
        }
        shared.latencies.lock().expect("lat").extend(self.local);
    }

    /// Count one exchange: a success keeps its latency, and its connection when
    /// connections are held open; a failure is recorded.
    fn settle(&mut self, outcome: Result<TlsStream, String>, started: Instant) {
        let shared = &self.shared;
        match outcome {
            Ok(stream) => {
                self.local.push(started.elapsed().as_micros() as u64);
                shared.ok.fetch_add(1, Ordering::Relaxed);
                if shared.keep_alive {
                    self.held = Some(stream);
                }
            }
            Err(msg) => shared.fail(msg),
        }
    }

    /// Send corpus entry `i` and read its reply, returning the connection it used.
    async fn exchange(&mut self, i: usize) -> Result<TlsStream, String> {
        let mut stream = match self.held.take() {
            Some(s) => s,
            None => self.connect().await?,
        };
        stream
            .write_all(&self.shared.corpus[i])
            .await
            .map_err(|e| format!("write: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;
        read_response(&mut stream, &mut self.buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        Ok(stream)
    }

    async fn connect(&self) -> Result<TlsStream, String> {
        let tcp = TcpStream::connect(&self.shared.target)
            .await
            .map_err(|e| format!("tcp connect: {e}"))?;
        let _ = tcp.set_nodelay(true);
        self.shared.handshakes.fetch_add(1, Ordering::Relaxed);
        let name = ServerName::try_from("localhost").expect("name");
        self.connector
            .connect(name, tcp)
            .await
            .map_err(|e| format!("tls handshake: {e}"))
    }
}
