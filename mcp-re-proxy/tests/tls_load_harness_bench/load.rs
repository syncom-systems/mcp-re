// SPDX-License-Identifier: Apache-2.0
//! Load generation and metrics: the run plan, the workers, the report and its JSON.

use super::*;

// --- load generation + metrics ------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Mode {
    Cold,
    KeepAlive,
}

impl Mode {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Mode::Cold => "cold",
            Mode::KeepAlive => "keepalive",
        }
    }
}

pub(super) struct LoadConfig {
    pub(super) concurrency: usize,
    pub(super) requests: usize,
    pub(super) mode: Mode,
    pub(super) hw_class: String,
    pub(super) cores: usize,
}

impl LoadConfig {
    /// The full-bench config, scaled from `MCP_RE_LOADGEN_*` env with the envelope
    /// defaults. The canonical envelope is the INVOLVED config (concurrency 128,
    /// 8000 requests, cold) — the SAME for local and GKE, so the two are directly
    /// comparable (MCPRE-110; the earlier 64/2000 GKE run was under-configured).
    pub(super) fn from_env() -> Self {
        let env_usize = |k: &str, default: usize| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        let mode = match std::env::var("MCP_RE_LOADGEN_MODE").ok().as_deref() {
            Some("keepalive") => Mode::KeepAlive,
            _ => Mode::Cold,
        };
        LoadConfig {
            concurrency: env_usize("MCP_RE_LOADGEN_CONCURRENCY", 128),
            requests: env_usize("MCP_RE_LOADGEN_REQUESTS", 8000),
            mode,
            hw_class: std::env::var("MCP_RE_LOADGEN_HW_CLASS")
                .unwrap_or_else(|_| "unspecified".to_string()),
            cores: env_usize(
                "MCP_RE_LOADGEN_CORES",
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
            ),
        }
    }
}

#[derive(Default)]
pub(super) struct Report {
    pub(super) successes: usize,
    pub(super) failures: usize,
    pub(super) reconnects: usize,
    wall: Duration,
    pub(super) p50_us: u128,
    p99_us: u128,
    pub(super) p999_us: u128,
    min_us: u128,
    mean_us: u128,
    max_us: u128,
    pub(super) throughput_rps: f64,
    reuse_fraction: f64,
}

/// `q`-quantile (0.0..=1.0) of a SORTED slice, by nearest-rank.
fn quantile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// What every load worker shares: the request counter, the collected latencies and the
/// failure and reconnect tallies, plus the plan the workers follow.
struct LoadState {
    pub(super) next: AtomicUsize,
    latencies: Mutex<Vec<u128>>,
    pub(super) failures: AtomicUsize,
    pub(super) reconnects: Arc<AtomicUsize>,
    pub(super) mode: Mode,
    total: usize,
}

impl LoadState {
    pub(super) fn new(cfg: &LoadConfig) -> Self {
        LoadState {
            next: AtomicUsize::new(0),
            latencies: Mutex::new(Vec::with_capacity(cfg.requests)),
            failures: AtomicUsize::new(0),
            reconnects: Arc::new(AtomicUsize::new(0)),
            mode: cfg.mode,
            total: cfg.requests,
        }
    }
}

/// Count one request that did not come back as a success.
fn tally_failure(state: &LoadState) {
    state.failures.fetch_add(1, Ordering::Relaxed);
}

/// One worker: pull request indices off the shared counter until `total` are done, timing
/// one round-trip each against the real listener, then publish its latencies.
fn load_worker(state: &LoadState, addr: SocketAddr, config: &Arc<ClientConfig>) {
    let mut local: Vec<u128> = Vec::new();
    let mut keep_alive = KeepAliveClient::new(Arc::clone(&state.reconnects));
    loop {
        let i = state.next.fetch_add(1, Ordering::Relaxed);
        if i >= state.total {
            break;
        }
        let signed = signed_request();
        let t0 = Instant::now();
        let outcome = match state.mode {
            Mode::Cold => cold_round_trip(addr, Arc::clone(config), &signed),
            Mode::KeepAlive => keep_alive.round_trip(addr, Arc::clone(config), &signed),
        };
        let dt = t0.elapsed();
        match outcome {
            Ok(reply) if is_success(&reply.body) => local.push(dt.as_micros()),
            _ => tally_failure(state),
        }
    }
    state
        .latencies
        .lock()
        .expect("latencies mutex")
        .extend(local);
}

/// Drive the workload: `concurrency` worker threads pull request indices off a
/// shared counter until `requests` are done, each timing one round-trip against
/// the real listener. Returns the aggregated [`Report`].
pub(super) fn run_load(addr: SocketAddr, config: Arc<ClientConfig>, cfg: &LoadConfig) -> Report {
    let state = Arc::new(LoadState::new(cfg));

    let start = Instant::now();
    let handles: Vec<_> = (0..cfg.concurrency)
        .map(|_| {
            let state = Arc::clone(&state);
            let config = Arc::clone(&config);
            std::thread::spawn(move || load_worker(&state, addr, &config))
        })
        .collect();

    for h in handles {
        h.join().expect("load worker panicked");
    }
    summarize(&state, start.elapsed(), cfg)
}

/// The mean of `samples`, or zero when there are none.
fn mean(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.iter().sum::<u128>() / samples.len() as u128
}

/// The aggregated [`Report`] of a finished run, computed once the workers have joined.
fn summarize(state: &LoadState, wall: Duration, cfg: &LoadConfig) -> Report {
    let mut samples = std::mem::take(&mut *state.latencies.lock().expect("latencies mutex"));
    samples.sort_unstable();

    let successes = samples.len();
    let failures = state.failures.load(Ordering::Relaxed);
    let reconnects = state.reconnects.load(Ordering::Relaxed);
    let throughput_rps = if wall.as_secs_f64() > 0.0 {
        successes as f64 / wall.as_secs_f64()
    } else {
        0.0
    };
    let reuse_fraction = if cfg.mode == Mode::KeepAlive && cfg.requests > 0 {
        1.0 - (reconnects as f64 / cfg.requests as f64)
    } else {
        0.0
    };

    Report {
        successes,
        failures,
        reconnects,
        wall,
        p50_us: quantile(&samples, 0.50),
        p99_us: quantile(&samples, 0.99),
        p999_us: quantile(&samples, 0.999),
        min_us: samples.first().copied().unwrap_or(0),
        mean_us: mean(&samples),
        max_us: samples.last().copied().unwrap_or(0),
        throughput_rps,
        reuse_fraction,
    }
}

pub(super) fn print_report(cfg: &LoadConfig, report: &Report) {
    println!("=== ADR-MCPRE-051 §7 load-harness report (RFC 9421 carrier, envelope v2) ===");
    println!("hardware_class     : {}", cfg.hw_class);
    println!(
        "declared_cores     : {} (per-core async fleet, SO_REUSEPORT; pinned via --cores, {})",
        cfg.cores,
        if cfg.cores == 0 {
            "0 = auto/one-per-core"
        } else {
            "workers served == this count"
        }
    );
    println!("connection_mode    : {}", cfg.mode.as_str());
    println!("concurrency        : {}", cfg.concurrency);
    println!("requests           : {}", cfg.requests);
    println!(
        "successes/failures : {}/{}",
        report.successes, report.failures
    );
    println!("wall_clock         : {:.3}s", report.wall.as_secs_f64());
    println!("throughput         : {:.1} req/s", report.throughput_rps);
    println!(
        "added_latency (us) : p50={} p99={} p999={} min={} mean={} max={}",
        report.p50_us, report.p99_us, report.p999_us, report.min_us, report.mean_us, report.max_us
    );
    if cfg.mode == Mode::KeepAlive {
        println!(
            "keepalive_reuse    : {:.3} ({} reconnects; 1.000 / 0 expected — the async data plane serves keep-alive and H2)",
            report.reuse_fraction, report.reconnects
        );
    }
    println!("per_core_scaling   : single point at {} core(s); drive MCP_RE_LOADGEN_CORES=1 then =N for the 1→N linear-scaling curve", cfg.cores);
}

/// Emit the report as machine-readable JSON to `MCP_RE_LOADGEN_OUT` when set, so a
/// run's numbers are attributable to the envelope that produced them.
pub(super) fn maybe_write_json(cfg: &LoadConfig, report: &Report) {
    let Some(path) = std::env::var("MCP_RE_LOADGEN_OUT")
        .ok()
        .filter(|p| !p.is_empty())
    else {
        return;
    };
    let doc = json!({
        "schema": "mcp-re-load-harness-report/v2",
        "envelope_version": 2,
        "envelope_ref": "docs/bench/adr-051-benchmark-envelope.json",
        "carrier": "rfc9421+rfc9530",
        "config": {
            "hardware_class": cfg.hw_class,
            "declared_cores": cfg.cores,
            "connection_mode": cfg.mode.as_str(),
            "concurrency": cfg.concurrency,
            "requests": cfg.requests,
            "replay_backend": REPLAY_DURABILITY_TIER,
            "tls_mode": "TLS1.3-mTLS",
        },
        "results": {
            "successes": report.successes,
            "failures": report.failures,
            "wall_clock_secs": report.wall.as_secs_f64(),
            "throughput_rps": report.throughput_rps,
            "added_latency_us": {
                "p50": report.p50_us, "p99": report.p99_us, "p999": report.p999_us,
                "min": report.min_us, "mean": report.mean_us, "max": report.max_us,
            },
            "keepalive_reuse_fraction": report.reuse_fraction,
        }
    });
    if let Err(e) = std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()) {
        eprintln!("load harness: could not write MCP_RE_LOADGEN_OUT={path}: {e}");
    }
}
