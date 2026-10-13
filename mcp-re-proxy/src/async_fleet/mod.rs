//! MCPRE-113 (ADR-MCPRE-051 §1, Phase 2) — per-core async serving fleet.
//!
//! The data-plane shape: **a small number of SHARDS, each a `tokio` runtime with a
//! work-stealing worker pool, its own `SO_REUSEPORT` listener and (on Linux)
//! CPU-affinity pinning, running one [`crate::async_serve::serve`] loop over one `Proxy`
//! per shard.** The kernel's `SO_REUSEPORT` group load-balances accepted connections
//! across the shard listeners, so there is:
//!
//!   * **no shared accept lock** — every core `accept()`s on its own listener fd;
//!   * **no cross-core connection handoff** — a connection is served start-to-finish
//!     on the core that accepted it;
//!   * **no contended cross-shard hot-path state** — each shard owns its runtime,
//!     its listener, and its `Proxy` handler; work stealing happens strictly WITHIN a
//!     shard's pool and never across shards. The ONLY state shared across shards is
//!     the coherent replay/trust store (designed server-side-atomic, ADR-MCPS-020)
//!     and the `ServerConfigSnapshot`/`ServerOptions` handles (shared read-only
//!     behind `Arc`). See the module-level "Cross-core sharing audit" below.
//!
//! This supersedes the MCPRE-112 single-shared-runtime scaffolding (which was never a
//! release, ADR-MCPRE-051 §1); that runtime remains available for development but the
//! fleet is the target and is what the SLO/scaling gate (MCPRE-110/123) measures.
//!
//! ## Cross-core sharing audit (acceptance criterion: "no cross-core locks on the
//! request path")
//!
//! Per request, a worker touches only:
//!   * its own shard's `tokio` runtime (uncontended across shards);
//!   * its own listener fd (per-shard, not shared);
//!   * the per-core `Proxy` handler (`make_handler(core)` returns a distinct handler
//!     per core; nothing forces cores to share one);
//!   * read-only `Arc<ServerConfigSnapshot>` / `Arc<ServerOptions>` (the TLS config is
//!     re-read per connection so a CRL hot-reload is picked up without a restart; an
//!     `Arc` clone is a non-blocking refcount bump, never a lock);
//!   * the shared authoritative replay/trust store, whose cross-core coordination is
//!     the store's own server-side-atomic contract (Redis/etcd), NOT a process-local
//!     lock on the request path. The in-memory reference store's interior `Mutex`
//!     (MCPRE-111) is the deliberate exception for the single-process dev tier and is
//!     out of scope for a fleet deployment, which mandates a shared store.
//!
//! ## Scope (this increment)
//!
//! Shard runtimes + `SO_REUSEPORT` + pinning + configurable shard count and pool depth,
//! with a
//! deterministic always-on suite proving N independent per-core runtimes serve the
//! full mTLS pipeline correctly and shut down cleanly. **Near-linear 1→N throughput
//! scaling is measured on the load harness (MCPRE-108) in the SLO/CI lane**, not in a
//! unit test (kernel connection distribution is platform-dependent and not a
//! deterministic assertion off Linux). Bounded graceful drain across cores is
//! MCPRE-115 (this increment inherits `serve`'s runtime-drop shutdown); per-core
//! bounded admission control is MCPRE-114.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::async_serve::serve;
use crate::async_serve::AsyncRequestHandler;
use crate::config_snapshot::ServerConfigSnapshot;
use crate::config_state::InFlightLimitBasis;
use crate::tls::ServerOptions;

mod core_runtime;
mod resolved_topology;
mod reuseport;

pub use core_runtime::CorePool;
pub use core_runtime::HandshakeBound;
pub use resolved_topology::ResolvedTopology;
use reuseport::reuseport_listener;

/// The `listen(2)` backlog for each per-core `SO_REUSEPORT` listener. A generous
/// default: the kernel bounds it to `net.core.somaxconn` anyway, and admission
/// control (MCPRE-114) is the real saturation guard, not the accept queue depth.
pub const DEFAULT_LISTEN_BACKLOG: i32 = 1024;

/// Configuration for a per-core serving fleet.
///
/// Each field is an owner's value carried whole: the shard shape the host resolved once,
/// and the admission basis layer A decided. Nothing here is a sentinel to interpret.
#[derive(Debug, Clone)]
pub struct FleetConfig {
    /// The address every per-core listener binds (they share one port via
    /// `SO_REUSEPORT`). A `:0` port is resolved to a concrete OS-assigned port on
    /// the first bind and reused for the rest, so the whole fleet shares one port.
    pub addr: SocketAddr,
    /// The shards and per-shard pool depth, resolved on this host by
    /// [`ResolvedTopology::resolve`].
    pub topology: ResolvedTopology,
    /// `listen(2)` backlog for each per-core listener.
    pub listen_backlog: i32,
    /// MCPRE-114: the admission limit, at whichever altitude the operator stated it. Every
    /// core enforces [`InFlightLimitBasis::per_core_ceiling`] for the resolved shard count,
    /// so admission stays lock-free ACROSS cores (no shared global semaphore on the hot
    /// path, per ADR-MCPRE-051 §1).
    pub in_flight: InFlightLimitBasis,
}

/// A running per-core fleet. Dropping it does NOT stop the workers (they would be
/// detached); call [`Fleet::shutdown_and_join`] (or [`Fleet::shutdown`] then
/// [`Fleet::join`]) to stop accepting and wait for the worker threads to exit.
pub struct Fleet {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Fleet {
    /// The concrete address (with resolved port) every core is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The number of per-core worker runtimes actually started.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Signal every per-core accept loop to stop. Each loop observes the flag within
    /// one accept poll interval and returns; in-flight connection tasks end when the
    /// per-core runtime is dropped (bounded graceful drain is MCPRE-115).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Join every worker thread (blocks until all per-core runtimes have exited).
    pub fn join(self) {
        for worker in self.workers {
            let _ = worker.join();
        }
    }

    /// Signal shutdown and join every worker thread.
    pub fn shutdown_and_join(self) {
        self.shutdown();
        self.join();
    }
}

/// One core's shape: the resolved depth, under the custody of the snapshot's signing key.
fn core_pool(topology: &ResolvedTopology, config: &ServerConfigSnapshot) -> CorePool {
    CorePool::for_core(topology.depth(), config.key_exposure())
}

/// Start a per-core serving fleet.
///
/// Binds one `SO_REUSEPORT` listener per resolved shard on one shared port,
/// and spawns one worker thread per listener; each worker pins itself (Linux), builds
/// a current-thread `tokio` runtime, and runs [`crate::async_serve::serve`] with the
/// per-core handler from `make_handler(core_index)`. Returns once every listener is
/// bound (so `fleet.local_addr()` is immediately usable) — the workers keep serving
/// until `shutdown` flips.
///
/// `make_handler` is called once per core with the core index, so callers construct
/// one `Proxy` (or handler) per core over the shared coherent stores rather than
/// contending on a single shared handler.
///
/// Fails closed at startup: any listener that cannot be bound (port in use without
/// `SO_REUSEPORT`, permission, address family unsupported), runtime that cannot be built
/// or worker that cannot be spawned fails the whole call with no core having served and
/// every started worker joined.
pub fn serve_fleet<H, F>(
    cfg: FleetConfig,
    config: Arc<crate::config_snapshot::ServerConfigSnapshot>,
    options: Arc<ServerOptions>,
    make_handler: F,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<Fleet>
where
    H: AsyncRequestHandler,
    F: Fn(usize) -> Arc<H>,
{
    let shards = cfg.topology.shards();
    let cores = shards.get();

    // MCPRE-114: every core enforces its own share of the admission limit; no shared
    // global semaphore.
    let options = with_per_core_ceiling(options, cfg.in_flight.per_core_ceiling(shards));

    // Every core of a fleet is the same shape, so it is decided once, and stated.
    let pool = core_pool(&cfg.topology, &config);
    if let Some(line) = pool.startup_line() {
        eprintln!("{line}");
    }
    let handshake_bound = pool.handshake_bound();

    // Bind the first listener to resolve the concrete port (cfg.addr may be `:0`),
    // then bind the remaining listeners to that resolved address so the whole fleet
    // shares ONE port via SO_REUSEPORT.
    let first = reuseport_listener(cfg.addr, cfg.listen_backlog)?;
    let bound = first.local_addr()?;
    let mut listeners = Vec::with_capacity(cores);
    listeners.push(first);
    for _ in 1..cores {
        listeners.push(reuseport_listener(bound, cfg.listen_backlog)?);
    }

    let workers = release_when_all_started(listeners, |core_index, listener, parked| {
        // Class R, and settled HERE because this is the thread that can still report a
        // failure. Neither is an invariant of this program — `build` allocates threads and
        // an event loop, `set_nonblocking` is an `fcntl` — and a core the OS declines must
        // not leave the fleet reporting a successful bind with one fewer server behind it.
        let runtime = pool.build_runtime(core_index)?;
        listener.set_nonblocking(true)?;
        let config = Arc::clone(&config);
        let options = Arc::clone(&options);
        let handler = make_handler(core_index);
        let shutdown = Arc::clone(&shutdown);
        let worker = std::thread::Builder::new()
            .name(format!("mcp-re-serve-{core_index}"))
            .spawn(move || {
                if parked.recv().is_err() {
                    return;
                }
                // Best-effort CPU pinning (Linux); a no-op elsewhere. Pinning is a
                // tail-latency optimization, never a correctness property, so a
                // failure to pin is ignored (logged nowhere hot).
                pin_current_thread_to_core(core_index);

                // `CorePool` decided which runtime this core got and how much blocking
                // handshake work it may admit onto it; both are stated there, once.
                runtime.block_on(serve_core(
                    listener,
                    config,
                    options,
                    handler,
                    shutdown,
                    handshake_bound,
                ));
            })?;
        Ok(worker)
    })?;

    Ok(Fleet {
        addr: bound,
        shutdown,
        workers,
    })
}

/// Register one core's listener with the runtime running it and serve on it.
async fn serve_core<H: AsyncRequestHandler>(
    listener: std::net::TcpListener,
    config: Arc<crate::config_snapshot::ServerConfigSnapshot>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    handshake_bound: HandshakeBound,
) {
    // Class A. `from_std` needs a non-blocking socket — established before the worker
    // thread was spawned — and a runtime context, which is the `block_on` that polls
    // this future. What remains is registration with the reactor this runtime owns, so a
    // failure is a defect in the lines above rather than anything an environment, peer or
    // configuration can produce.
    #[allow(clippy::expect_used)]
    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("the listener registers with the runtime running it");
    serve(
        listener,
        config,
        options,
        handler,
        shutdown,
        handshake_bound,
    )
    .await;
}

/// Drop every parked worker's sender, so each returns without serving, and join them.
fn stand_down(started: Vec<(JoinHandle<()>, std::sync::mpsc::SyncSender<()>)>) {
    let handles: Vec<JoinHandle<()>> = started
        .into_iter()
        .map(|(handle, release)| {
            drop(release);
            handle
        })
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
}

/// Start one worker per item, each parked until every worker has started.
///
/// `start` receives the index, the item and the receiver the worker must wait on before
/// serving. If any `start` fails, every parked worker's sender is dropped (its `recv`
/// errs and it returns without serving), every started handle is joined, and the error is
/// returned: no worker serves and none outlives the call. Only once all have started is
/// each released.
fn release_when_all_started<T>(
    items: impl IntoIterator<Item = T>,
    mut start: impl FnMut(usize, T, std::sync::mpsc::Receiver<()>) -> std::io::Result<JoinHandle<()>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut started = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        let (release, parked) = std::sync::mpsc::sync_channel::<()>(1);
        match start(index, item, parked) {
            Ok(handle) => started.push((handle, release)),
            Err(error) => {
                stand_down(started);
                return Err(error);
            }
        }
    }
    let mut handles = Vec::with_capacity(started.len());
    for (handle, release) in started {
        let _ = release.send(());
        handles.push(handle);
    }
    Ok(handles)
}

/// `options` with every core's in-flight ceiling set to `ceiling`, rebuilt only when that
/// changes it.
fn with_per_core_ceiling(
    options: Arc<ServerOptions>,
    ceiling: std::num::NonZeroUsize,
) -> Arc<ServerOptions> {
    if options.limits.max_in_flight_requests == Some(ceiling.get()) {
        return options;
    }
    let mut opts = (*options).clone();
    opts.limits.max_in_flight_requests = Some(ceiling.get());
    Arc::new(opts)
}

/// Pin the calling thread to `core_index % online_cpus` (Linux `sched_setaffinity`).
/// Best-effort: pinning is a tail-latency optimization (keep a worker on one core so
/// its runtime, sockets, and cache lines stay warm), never a correctness property, so
/// every failure — an unavailable syscall, a restricted cgroup cpuset — is ignored.
#[cfg(target_os = "linux")]
fn pin_current_thread_to_core(core_index: usize) {
    // `checked_rem`, so the guard and the operation are ONE statement. `online_cpu_count`
    // returns 0 only if every fallback in it failed, and nothing can be pinned to then.
    let Some(cpu) = core_index.checked_rem(online_cpu_count()) else {
        return;
    };
    // SAFETY: `cpu_set` is a zeroed, fully-owned `cpu_set_t`; `CPU_SET` sets one valid
    // bit in it; `sched_setaffinity(0, ...)` applies it to the calling thread and does
    // not retain the pointer. Return value is ignored (best-effort).
    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpu_set);
        let _ = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set as *const libc::cpu_set_t,
        );
    }
}

/// Non-Linux platforms: no portable thread-affinity syscall; pinning is a no-op (the
/// per-core runtimes + `SO_REUSEPORT` still apply — only the affinity hint is
/// skipped). Matches the target-gated posture of the Linux sandbox backend.
#[cfg(not(target_os = "linux"))]
fn pin_current_thread_to_core(_core_index: usize) {}

/// Number of online CPUs, for the pinning modulo. `sysconf(_SC_NPROCESSORS_ONLN)`;
/// falls back to `available_parallelism` and finally 1.
#[cfg(target_os = "linux")]
fn online_cpu_count() -> usize {
    // SAFETY: `sysconf` takes an int name and returns a long; no pointers involved.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod snapshot_custody_tests {
    use super::*;
    use rustls::crypto::ring;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    /// A self-signed server-only config built in-process. Nothing here performs a
    /// handshake — it exists because the core's shape is read from a snapshot.
    fn dummy_snapshot(
        key_exposure: crate::config_state::PrivateKeyExposure,
    ) -> Arc<crate::config_snapshot::ServerConfigSnapshot> {
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key_der)
                .expect("server config");
        Arc::new(crate::config_snapshot::ServerConfigSnapshot::new(
            Arc::new(config),
            key_exposure,
        ))
    }

    /// One shard of one worker, the depth a single-cpu host derives.
    fn single_worker() -> ResolvedTopology {
        let mut request = crate::config_state::test_support::legal_config();
        request.cores = 1;
        request.workers_per_shard = 1;
        ResolvedTopology::resolve(crate::config_state::topology::classify(&request).1)
    }

    /// THE SERVED SNAPSHOT'S CUSTODY decides the core's shape. The same one-worker topology
    /// is a share-nothing core over an exported key and a bounded pool over a delegated
    /// one, so a delegated snapshot is never served on a runtime shaped for an in-memory key.
    #[test]
    fn the_core_shape_follows_the_served_snapshots_custody() {
        let delegated = core_pool(
            &single_worker(),
            &dummy_snapshot(crate::config_state::PrivateKeyExposure::NonExporting),
        );
        assert!(delegated.handshake_bound().permits().is_some());
        assert!(delegated.startup_line().is_some());

        let exported = core_pool(
            &single_worker(),
            &dummy_snapshot(crate::config_state::PrivateKeyExposure::ProcessReadable),
        );
        assert!(exported.handshake_bound().permits().is_none());
        assert!(exported.startup_line().is_none());
    }
}

#[cfg(test)]
mod start_gate_tests {
    use super::release_when_all_started;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    #[test]
    fn a_core_that_fails_to_start_leaves_every_started_core_unserved_and_joined() {
        let served = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicUsize::new(0));
        let result = release_when_all_started([0, 1, 2], |index, _item, parked| {
            if index == 2 {
                return Err(std::io::Error::other("declined"));
            }
            let served = Arc::clone(&served);
            let exited = Arc::clone(&exited);
            Ok(std::thread::spawn(move || {
                if parked.recv().is_err() {
                    exited.fetch_add(1, SeqCst);
                    return;
                }
                served.store(true, SeqCst);
            }))
        });
        let error = result.expect_err("the third core declines to start");
        assert!(error.to_string().contains("declined"));
        assert!(!served.load(SeqCst));
        assert_eq!(exited.load(SeqCst), 2);
    }

    #[test]
    fn every_core_is_released_once_all_have_started() {
        let served = Arc::new(AtomicUsize::new(0));
        let handles = release_when_all_started([0, 1, 2], |_index, _item, parked| {
            let served = Arc::clone(&served);
            Ok(std::thread::spawn(move || {
                if parked.recv().is_ok() {
                    served.fetch_add(1, SeqCst);
                }
            }))
        })
        .expect("every core starts");
        for handle in handles {
            handle.join().expect("the worker exits cleanly");
        }
        assert_eq!(served.load(SeqCst), 3);
    }
}
