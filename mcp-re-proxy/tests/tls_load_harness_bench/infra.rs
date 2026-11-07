// SPDX-License-Identifier: Apache-2.0
//! What the harness stands up around the proxy: the echo backend, the Redis fleet, the spawned CLI and in-process apps.

use super::*;

// --- runfiles binary resolution + spawned CLI (killed on drop) ----------------

fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

// --- in-process HTTP echo inner backend (ADR-MCPRE-051 §3) --------------------
//
// The proxy serves on the async fleet and forwards each verified request over HTTP
// to a stateless inner backend. It reads the POSTed JSON-RPC request and answers
// with a JSON-RPC result echoing the method, so a success ("no error") still
// corresponds to a genuinely signed inner result. The proxy strips the top-level
// `_meta` request-evidence block before forwarding (RFC 9421 serving path), so the
// inner sees clean MCP. Mirrors the in-process hyper backend in `http_inner_test.rs`.
async fn echo_inner_service(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").cloned().unwrap_or(Value::Null);

    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "echoed_method": method, "ok": true },
    });
    let bytes = serde_json::to_vec(&response).unwrap_or_default();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("response builds"))
}

/// Start the in-process HTTP echo backend on an ephemeral `127.0.0.1` port and
/// return its bound address. Runs on its own multi-thread tokio runtime on a
/// detached daemon thread (lives for the rest of the test process), so it can
/// absorb the harness's concurrent load without starving.
pub(super) fn spawn_http_echo_backend() -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("backend runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind echo backend");
            let addr = listener.local_addr().expect("backend addr");
            tx.send(addr).expect("send backend addr");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service_fn(echo_inner_service))
                        .await;
                });
            }
        });
    });
    rx.recv().expect("echo backend did not report its address")
}

pub(super) struct ProxyProcess {
    child: std::process::Child,
    pub(super) addr: SocketAddr,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `app::run` serving on a background thread at a pre-chosen address, the way `main` runs it.
pub(super) struct RunningApp {
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) handle: std::thread::JoinHandle<()>,
    pub(super) addr: SocketAddr,
}

impl RunningApp {
    /// Start `argv` and wait until `bind` accepts connections.
    pub(super) fn start(argv: &[String], bind: &str) -> RunningApp {
        let config = mcp_re_proxy::cli::parse_args(argv).expect("parse config");
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            let _ = mcp_re_proxy::app::run(config, sd);
        });
        let addr: SocketAddr = bind.parse().expect("bind addr");
        assert!(accepting(addr), "app::run did not bind {addr}");
        RunningApp {
            shutdown,
            handle,
            addr,
        }
    }

    /// Signal shutdown and wait for the drain.
    pub(super) fn stop(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.handle.join();
    }
}

// --- Redis wait-quorum fleet (integration infra, brought up + torn down here) ----

/// Run `docker` with `args`, returning its captured output. Fails the test with a
/// clear message if the `docker` CLI is unavailable — this is an integration test
/// and Docker is part of its milieu.
fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "docker is required to run the load-harness integration test (bringing up the \
             Redis wait-quorum replay fleet), but invoking `docker {}` failed: {e}",
                args.join(" ")
            )
        })
}

/// A Redis primary + 2 replicas on a private Docker network, published on an
/// ephemeral host port. The `redis-wait-quorum:2:*` durability tier the proxy
/// requires needs 2 replica acks, so a single node cannot satisfy it — this mirrors
/// `tools/http_profile_multireplica_proof.sh`. Every container is removed and the
/// network torn down on `Drop`, so a panicking test leaks nothing.
pub(super) struct RedisFleet {
    pub(super) net: String,
    pub(super) containers: Vec<String>,
    /// Host port publishing the primary's 6379.
    host_port: u16,
}

/// The labels that stamp every resource a fleet creates with the run that owns it.
///
/// OWNERSHIP IS A LABEL, NOT A NAME.
///
/// The fleet's creation previously removed `primary`/`r1`/`r2` and called it "cleaning any
/// stale artifacts from a previous aborted run". It could never do that: the names are
/// built from the CURRENT process id, so they cannot match a prior run's containers. The
/// cleanup was unreachable by construction while reading as though it worked, which is
/// worse than no cleanup at all.
///
/// Reconciling a previous run is now the SUPERVISOR's job (tools/slo/run_supervisor.py),
/// which runs outside the test binary and can therefore still act when this process has been
/// killed. What happens here is the half only this process can do: stamp every
/// resource with the run that owns it, so something outside can find them later.
///
/// `unowned-local` marks a developer run with no supervisor. It is deliberately a
/// distinct value rather than an empty label: "created by a local run" and "created
/// by an authoritative run whose id was lost" must not look the same to reconciliation.
fn ownership_labels() -> Vec<String> {
    let run_id = std::env::var("MCP_RE_SLO_RUN_ID").unwrap_or_else(|_| "unowned-local".to_string());
    vec![
        "--label".to_string(),
        "com.mcp-re.slo=true".to_string(),
        "--label".to_string(),
        format!("com.mcp-re.slo.run={run_id}"),
    ]
}

/// Disk persistence is REQUIRED: the replay store's whole purpose is to remember admitted
/// nonces, and default disk-based replication only completes when the primary persists
/// (otherwise replicas stall and WAIT returns 0).
const REDIS_PERSIST_ARGS: [&str; 6] = [
    "--appendonly",
    "yes",
    "--appendfsync",
    "everysec",
    "--save",
    "60 1000 300 10",
];

/// The private Docker network a fleet lives on, and the labels that stamp what runs on it.
struct FleetNet {
    name: String,
    labels: Vec<String>,
}

impl FleetNet {
    /// Create the network `name`, stamped with this run's ownership labels.
    fn create(name: String) -> FleetNet {
        let labels = ownership_labels();
        let mut create: Vec<&str> = vec!["network", "create"];
        create.extend(labels.iter().map(String::as_str));
        create.push(&name);
        let created = docker(&create);
        assert!(
            created.status.success(),
            "docker network create failed (is the Docker daemon running?): {}",
            String::from_utf8_lossy(&created.stderr)
        );
        FleetNet { name, labels }
    }

    /// Start `node` on this network, stamped with its labels. The container must start.
    fn run(&self, node: &RedisNode) {
        let mut args: Vec<&str> = vec!["run", "-d"];
        args.extend(self.labels.iter().map(String::as_str));
        args.extend(["--name", node.name, "--network", &self.name]);
        args.extend(node.publish);
        args.extend(["redis:7-alpine", "redis-server"]);
        args.extend(node.server_args);
        args.extend(REDIS_PERSIST_ARGS);
        let out = docker(&args);
        assert!(
            out.status.success(),
            "run redis {}: {}",
            node.name,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// One Redis node of the fleet. `publish` is the docker flags that publish a port and
/// `server_args` the redis-server flags that come before persistence.
struct RedisNode<'a> {
    name: &'a str,
    publish: &'a [&'a str],
    server_args: &'a [&'a str],
}

impl RedisNode<'_> {
    /// The ephemeral host port publishing this node's 6379.
    fn published_port(&self) -> u16 {
        let port_out = docker(&["port", self.name, "6379/tcp"]);
        let mapping = String::from_utf8_lossy(&port_out.stdout);
        mapping
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .unwrap_or_else(|| {
                panic!("could not parse published redis port from `docker port`: {mapping:?}")
            })
    }

    /// Wait until BOTH replicas report state=online, so the `WAIT 2` in the durability tier
    /// gets 2 acks rather than timing out on every request. This node is the primary.
    fn await_replicas_online(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let info = docker(&["exec", self.name, "redis-cli", "info", "replication"]);
            let online = String::from_utf8_lossy(&info.stdout)
                .matches("state=online")
                .count();
            if online >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "redis replicas did not come online within budget"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

impl RedisFleet {
    pub(super) fn start() -> RedisFleet {
        // Unique per FLEET, not per process: libtest runs the tests in this binary
        // concurrently (same PID), so a process-id-only name would collide between
        // `load_harness_smoke` and `tls_load_harness_bench`. A per-instance sequence
        // makes every fleet's network + container names distinct.
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = format!(
            "{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let net = FleetNet::create(format!("mcp-re-loadgen-net-{id}"));
        let primary_name = format!("mcp-re-loadgen-redis-primary-{id}");
        let r1 = format!("mcp-re-loadgen-redis-r1-{id}");
        let r2 = format!("mcp-re-loadgen-redis-r2-{id}");

        let primary = RedisNode {
            name: &primary_name,
            publish: &["-p", "0:6379"],
            server_args: &[],
        };
        net.run(&primary);
        for r in [&r1, &r2] {
            let replica_of = ["--replicaof", primary_name.as_str(), "6379"];
            net.run(&RedisNode {
                name: r,
                publish: &[],
                server_args: &replica_of,
            });
        }

        let host_port = primary.published_port();
        let fleet = RedisFleet {
            net: net.name,
            containers: vec![primary_name.clone(), r1, r2],
            host_port,
        };
        primary.await_replicas_online();
        fleet
    }

    pub(super) fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.host_port)
    }
}

impl Drop for RedisFleet {
    /// The FAST path, not the guarantee.
    ///
    /// This releases the fleet in milliseconds on a normal exit and on a panic, which is
    /// worth having. It cannot run on SIGKILL, on a cancelled job whose process group is
    /// killed, or when the runner dies -- so it is not what makes the plane clean. That is
    /// the supervisor's clean-end gate, which verifies by label rather than trusting a
    /// destructor to have executed.
    ///
    /// `-v` removes the container's anonymous volumes too: redis runs with `appendonly
    /// yes`, so every container owns one, and `rm -f` alone leaks them one fleet at a time.
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = docker(&["rm", "-fv", c]);
        }
        let _ = docker(&["network", "rm", &self.net]);
    }
}

/// What `args` does not state is the same for every proxy this harness starts: the
/// maximal-security posture on fixtures, over the shared Redis replay tier, forwarding to the
/// in-process echo backend. What varies is a field; anything else a case needs is appended.
pub(super) struct Deployment<'a> {
    material: &'a Material,
    pub(super) trust: &'a std::path::Path,
    bind: &'a str,
    upstream: Upstream<'a>,
    pub(super) cores: usize,
}

/// What a proxy under test talks to: the inner backend it forwards to and the shared Redis
/// replay tier.
#[derive(Clone, Copy)]
pub(super) struct Upstream<'a> {
    pub(super) inner_http_url: &'a str,
    pub(super) redis_url: &'a str,
}

impl<'a> Deployment<'a> {
    /// A single-core deployment trusting the material's own trust document.
    pub(super) fn new(material: &'a Material, bind: &'a str, upstream: Upstream<'a>) -> Self {
        Deployment {
            material,
            trust: &material.trust_path,
            bind,
            upstream,
            cores: 1,
        }
    }

    pub(super) fn args(&self) -> Vec<String> {
        let material = self.material;
        // ADR-MCPRE-051 §1/§7: PIN the per-core worker count so `declared_cores` in the
        // report is the count actually served, and so the 1→N linear-scaling curve is
        // reproducible — run the bench at MCP_RE_LOADGEN_CORES=1 then =N. `0` = auto.
        let cores_str = self.cores.to_string();
        // The proxy always runs the maximal-security posture, so the bench config must be
        // production-valid. The cert-lifetime arg is the SAME constant the proxy enforces
        // (`config_state::client_credential_window::MAX_CLIENT_CERT_LIFETIME`), and the client leaf
        // `build_client_config` mints has a span within it — no hand-picked magic number. The
        // per-core async serving plane refuses node-local replay (memory + file), so the ONLY
        // valid replay backend is a shared store; this bench is `#[ignore]` infra-lane and, when
        // run, needs a Redis reachable at MCP_RE_LOADGEN_REDIS_URL and a CLI built with
        // `--features redis_replay`.
        let cert_lifetime = MAX_CLIENT_CERT_LIFETIME.as_secs().to_string();
        owned(&[
            "--bind",
            self.bind,
            "--allow-example-fixtures",
            "--audience",
            AUDIENCE,
            "--server-signer",
            SERVER,
            "--server-key-id",
            SERVER_KEY_ID,
            // Delegated-required is the ONLY response-signing mode (ADR-MCPRE-052 §7):
            // the trust epoch minted into every delegation credential is mandatory.
            "--delegated-trust-epoch",
            "epoch-1",
            "--key-source",
            "file",
            "--signing-key-seed",
            &material.seed_path.to_string_lossy(),
            "--tls-cert",
            &material.server_cert_path.to_string_lossy(),
            "--tls-key",
            &material.server_key_path.to_string_lossy(),
            "--client-ca",
            &material.client_ca_path.to_string_lossy(),
            "--trust",
            &self.trust.to_string_lossy(),
            // RFC 9421 serving path: the audience `@target-uri` both sides sign over,
            // and the trust domain the resolved client/server actor_id is built under.
            "--target-uri",
            TARGET_URI,
            "--mcp-protocol-version",
            "2026-07-28",
            "--trust-domain",
            TRUST_DOMAIN,
            // The enforced ceiling itself — the client leaf's span is minted within it.
            "--max-client-cert-lifetime",
            &cert_lifetime,
            // Shared replay: the per-core async plane refuses node-local caches. The
            // fleet has 2 replicas, so `WAIT 2` is satisfiable.
            "--replay-redis-url",
            self.upstream.redis_url,
            "--replay-durability-tier",
            REPLAY_DURABILITY_TIER,
            "--cores",
            &cores_str,
            // ADR-MCPRE-051 §3: serve on the async fleet forwarding to the stateless
            // in-process HTTP echo backend.
            "--inner-http-url",
            self.upstream.inner_http_url,
        ])
    }
}

pub(super) fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

/// A free local address, chosen up front so a client knows where to connect (`app::run`
/// blocks and does not surface its bound address).
pub(super) fn free_bind() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("free port")
        .local_addr()
        .expect("addr")
        .port();
    format!("127.0.0.1:{port}")
}

/// Whether `addr` starts accepting connections within the budget (200 x 25 ms).
fn accepting(addr: SocketAddr) -> bool {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Drain the child's stderr on a thread into a shared buffer, so a full pipe never blocks it.
fn capture_stderr(child: &mut std::process::Child) -> Arc<Mutex<String>> {
    let stderr_buf = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&stderr_buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut buf) = sink.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });
    stderr_buf
}

/// The address the CLI reports serving on, read from its captured stderr. Panics, with what
/// the CLI said, if it exits first or reports nothing within the budget.
fn await_serving_addr(child: &mut std::process::Child, stderr_buf: &Mutex<String>) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(a) = stderr_buf.lock().ok().and_then(|b| parse_serving_addr(&b)) {
            return a;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcp_re_proxy_cli exited before serving (status {status}):\n{captured}");
        }
        if Instant::now() > deadline {
            let captured = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
            let _ = child.kill();
            panic!("mcp_re_proxy_cli did not report a serving address within budget:\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn spawn_proxy(material: &Material, upstream: Upstream, cores: usize) -> ProxyProcess {
    let cli = locate("MCP_RE_PROXY_CLI");

    // ADR-MCPRE-051 §1 second topology axis. Default "0" keeps the single-threaded
    // share-nothing shard, so an unset environment measures exactly what the committed
    // anchor measured and the gate stays a like-for-like comparison.
    let workers_per_shard =
        std::env::var("MCP_RE_LOADGEN_WORKERS_PER_SHARD").unwrap_or_else(|_| "0".to_string());

    // Bind an EPHEMERAL port and read the resolved address back from the CLI's own
    // `async fleet serving on <addr>` stderr line — race-free (the fleet owns the
    // port from bind onward), unlike a bind-release-rebind `free_port()`.
    let mut deployment = Deployment::new(material, "127.0.0.1:0", upstream);
    deployment.cores = cores;
    let mut args = deployment.args();
    args.extend(owned(&[
        "--transport-binding",
        "exact",
        "--transport-identity-source",
        "uri_san",
        "--workers-per-shard",
        &workers_per_shard,
    ]));
    let mut child = Command::new(&cli)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp_re_proxy_cli");

    let stderr_buf = capture_stderr(&mut child);
    let addr = await_serving_addr(&mut child, &stderr_buf);
    assert!(
        accepting(addr),
        "mcp_re_proxy_cli listening address {addr} is not accepting connections"
    );

    ProxyProcess { child, addr }
}

/// Parse the CLI's `... async fleet serving on <addr> (...)` stderr line into the
/// bound [`SocketAddr`].
fn parse_serving_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "async fleet serving on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(char::is_whitespace)?;
    rest[..end].parse::<SocketAddr>().ok()
}
