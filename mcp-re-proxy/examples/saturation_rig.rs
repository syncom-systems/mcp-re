// SPDX-License-Identifier: Apache-2.0
//! Saturation rig orchestrator — the instrument that can measure the proxy's own ceiling.
//!
//! The ADR-MCPRE-051 §7 harness cannot, and this is not a criticism of it: it is a
//! REGRESSION DETECTOR, deliberately cold and deliberately self-contained, and its numbers
//! are only meaningful relative to an anchor measured the same way. It stays untouched.
//!
//! What it cannot answer is "how fast is the proxy", because it co-locates a
//! thread-per-connection client that signs on the hot path with the proxy and the backend
//! in one process. Throughput measured that way was flat at ~10.4k rps across 1-8 proxy
//! cores AND 128-1024 connections — a ceiling that moves with neither cores nor offered
//! load is the harness, not the subject.
//!
//! This rig separates every tier into its own process so each one's CPU is attributable,
//! and it refuses to report a throughput number it cannot show is the proxy's:
//!
//! * proxy — a spawned `mcp-re-proxy` with `--cores K`, the swept variable;
//! * backend — its own process, worker count set well above the proxy's;
//! * generators — M separate processes, async, corpus pre-signed before the clock starts.
//!
//! # The saturation proof
//!
//! Every sweep point runs at M and M+1 generators. If throughput RISES when a generator
//! is added, the client was the limit and the number is discarded as a floor. Only a point
//! where adding load does not add throughput is reported as the proxy's. This is the check
//! whose absence made every previous number unsafe, so it is not optional here.
//!
//! # Liveness (`--smoke`)
//!
//! `--smoke` is not a measurement and never prints a throughput number. It stands the same
//! three tiers up with the same fixtures, the same admission posture and the same replay
//! tier, sends a tiny fixed load, and asserts that the requests were SERVED: zero failures,
//! a non-zero rate, and backend CPU that moved. It exists because the instrument once sat
//! for eleven days constructing a request the serving path refused at the channel-binding
//! stage — 100% refused, no backend dispatch, and every ordinary gate green, because
//! nothing on the merge path ever asked the rig to send one request.
//!
//! # Honest limits
//!
//! macOS has no usable CPU affinity for user processes, so tiers share the machine's
//! scheduler and "the proxy got K cores" means "the proxy was configured for K per-core
//! workers", not that the OS reserved them. On a single box the generators still compete
//! for CPU; the M/M+1 check is what detects when that has begun to bind, and per-process
//! CPU is reported so the reader can see it rather than trust it.

#[path = "saturation_rig/generators.rs"]
mod generators;
#[path = "saturation_rig/material.rs"]
mod material;
#[path = "saturation_rig/options.rs"]
mod options;
#[path = "saturation_rig/proc.rs"]
mod proc;
#[path = "saturation_rig/proxy.rs"]
mod proxy;
#[path = "saturation_rig/rig.rs"]
mod rig;
#[path = "saturation_rig/smoke.rs"]
mod smoke;
#[path = "saturation_rig/sweep.rs"]
mod sweep;

use material::write_material;
use options::Options;
use proc::runfile;
use proc::spawn_backend;
use rig::Rig;
use smoke::run_smoke;
use sweep::run_sweep;

fn main() {
    let opts = Options::from_env_and_args();

    let gen_exe = runfile("MCP_RE_SAT_LOADGEN");
    let backend_exe = runfile("MCP_RE_SAT_BACKEND");
    let proxy_cli = runfile("MCP_RE_PROXY_CLI");

    let material = write_material();
    let (backend, backend_addr) = spawn_backend(&backend_exe, opts.backend_workers);
    let rig = Rig {
        proxy_cli,
        gen_exe,
        material,
        redis: opts.redis.clone(),
        backend_addr,
        backend_pid: backend.pid(),
        tier: opts.tier.clone(),
    };

    println!("replay tier {}", opts.tier);
    if opts.smoke {
        let rc = run_smoke(&rig);
        drop(backend);
        std::process::exit(rc);
    }
    run_sweep(&rig, &opts);
}
