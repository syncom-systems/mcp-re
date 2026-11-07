// SPDX-License-Identifier: Apache-2.0
//! The measured sweep: one proxy per core count, generators escalated until the client
//! stops being the limit, and the report.

use std::time::Duration;

use serde_json::json;
use serde_json::Value;

use super::generators::Load;
use super::generators::Measurement;
use super::options::Options;
use super::proc::cpu_secs;
use super::rig::Rig;

/// What a point is measured against: the proxy's address and the load each generator offers.
struct Offered<'a> {
    target: &'a str,
    load: Load<'a>,
}

/// A row's classification. `Invalid` outranks the other two: a throughput figure
/// computed over a run that dropped requests is not a measurement of anything.
#[derive(Clone, Copy, PartialEq)]
enum Verdict {
    Client,
    Proxy,
    Invalid,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Client => "CLIENT",
            Verdict::Proxy => "PROXY",
            Verdict::Invalid => "INVALID",
        }
    }
}

/// The point a generator count settled on, before the row is classified as valid.
struct Point {
    gens: usize,
    measured: Measurement,
    gain: Option<f64>,
    saturated: bool,
}

/// One finished row of the sweep.
struct Row {
    cores: usize,
    point: Point,
    verdict: Verdict,
    fail_pct: f64,
    proxy_cpu: f64,
    backend_cpu: f64,
}

fn gain_of(next: f64, base: f64) -> Option<f64> {
    Some((next - base) / base.max(1.0) * 100.0).filter(|g| !g.is_nan())
}

/// Pin the row to `n` generators and probe once at `n + 1` purely to classify it; the
/// reported number stays the pinned-N one so the curve remains comparable.
fn fixed_point(rig: &Rig, offered: &Offered, opts: &Options, n: usize) -> Point {
    let measured = rig.generate(offered.target, n, &offered.load);
    let probe = rig.generate(offered.target, n + 1, &offered.load);
    let gain = gain_of(probe.rps, measured.rps);
    Point {
        gens: n,
        measured,
        gain,
        saturated: !gain.is_some_and(|g| g > opts.saturation_pct),
    }
}

/// ESCALATE until the client stops being the limit. Testing only M and M+1 tells you the
/// point is a floor but not where the ceiling is; adding generators until throughput
/// stops responding is what turns a floor into a measurement.
fn escalated_point(rig: &Rig, offered: &Offered, opts: &Options) -> Point {
    let mut gens = opts.generators;
    let mut current = rig.generate(offered.target, gens, &offered.load);
    let mut gain = None;
    while gens < opts.max_generators {
        let next = rig.generate(offered.target, gens + 1, &offered.load);
        gain = gain_of(next.rps, current.rps);
        if gain.is_some_and(|g| g <= opts.saturation_pct) {
            // The extra generator bought nothing: the proxy is the limit, and the
            // HIGHER of the two is the honest number.
            if next.rps > current.rps {
                current = next;
                gens += 1;
            }
            return Point {
                gens,
                measured: current,
                gain,
                saturated: true,
            };
        }
        gens += 1;
        current = next;
    }
    Point {
        gens,
        measured: current,
        gain,
        saturated: false,
    }
}

fn measure_point(rig: &Rig, target: &str, opts: &Options) -> Point {
    let offered = Offered {
        target,
        load: Load {
            connections: opts.connections,
            requests: opts.requests,
            mode: &opts.mode,
        },
    };
    match opts.fixed_generators {
        Some(n) => fixed_point(rig, &offered, opts, n),
        None => escalated_point(rig, &offered, opts),
    }
}

fn classify(point: &Point, requests: usize) -> (Verdict, f64) {
    let attempted = point.gens * requests;
    let fail_pct = point.measured.failed as f64 / attempted.max(1) as f64 * 100.0;
    let verdict = if fail_pct > 0.5 {
        Verdict::Invalid
    } else if point.saturated {
        Verdict::Proxy
    } else {
        Verdict::Client
    };
    (verdict, fail_pct)
}

fn measure_row(rig: &Rig, opts: &Options, cores: usize) -> Row {
    let headroom = (opts.max_generators * opts.connections * 2).max(1024);
    let (proxy, target) = rig.spawn_proxy(cores, headroom);
    let proxy_pid = proxy.pid();
    std::thread::sleep(Duration::from_millis(300));

    let p0 = cpu_secs(proxy_pid);
    let b0 = rig.backend_cpu();
    let point = measure_point(rig, &target, opts);
    let p2 = cpu_secs(proxy_pid);
    let b1 = rig.backend_cpu();

    let (verdict, fail_pct) = classify(&point, opts.requests);
    drop(proxy);
    std::thread::sleep(Duration::from_millis(200));
    Row {
        cores,
        point,
        verdict,
        fail_pct,
        proxy_cpu: p2 - p0,
        backend_cpu: b1 - b0,
    }
}

fn print_header() {
    println!(
        "{:>5} {:>4} {:>11} {:>11} {:>9} {:>9} {:>8} {:>9} {:>9}",
        "cores", "gens", "rps", "last_gain", "verdict", "p50_us", "fail", "proxy_cpu", "gen_cpu"
    );
}

fn print_row(row: &Row) {
    let Row {
        cores,
        point,
        verdict,
        proxy_cpu,
        ..
    } = row;
    let gain = point
        .gain
        .map_or_else(|| "-".to_string(), |g| format!("{g:+.1}%"));
    println!(
        "{cores:>5} {:>4} {:>11.1} {gain:>11} {:>9} {:>9} {:>8} {proxy_cpu:>9.1} {:>9.1}",
        point.gens,
        point.measured.rps,
        verdict.label(),
        point.measured.p50,
        point.measured.failed,
        point.measured.cpu
    );
}

fn row_json(row: &Row) -> Value {
    let point = &row.point;
    json!({
        "cores": row.cores, "generators": point.gens,
        "rps": point.measured.rps,
        "last_gain_pct": point.gain.map_or(Value::Null, |g| json!(g)),
        "saturated": row.verdict == Verdict::Proxy,
        "failure_pct": row.fail_pct,
        "p50_us": point.measured.p50, "failures": point.measured.failed,
        "proxy_cpu_secs": row.proxy_cpu, "backend_cpu_secs": row.backend_cpu,
        "generator_cpu_secs": point.measured.cpu,
    })
}

fn write_report(opts: &Options, rows: &[Row]) {
    let report = json!({
        "schema": "mcp-re-saturation-rig/v1",
        "mode": opts.mode, "connections_per_generator": opts.connections,
        "requests_per_generator": opts.requests, "backend_workers": opts.backend_workers,
        "note": "NOT comparable to the ADR-MCPRE-051 §7 anchor — different client, different question.",
        "points": rows.iter().map(row_json).collect::<Vec<_>>(),
    });
    let path = std::env::var("MCP_RE_SAT_OUT").unwrap_or_else(|_| "target/saturation.json".into());
    std::fs::write(&path, serde_json::to_string_pretty(&report).expect("json")).expect("write");
    println!("\nwrote {path}");
    println!("verdict CLIENT = adding a generator raised throughput >5%; that row is a FLOOR, not the proxy's ceiling.");
}

pub(super) fn run_sweep(rig: &Rig, opts: &Options) {
    println!(
        "saturation rig — mode={} connections/gen={} requests/gen={}",
        opts.mode, opts.connections, opts.requests
    );
    println!(
        "backend on {} ({} workers)\n",
        rig.backend_addr, opts.backend_workers
    );
    print_header();
    let mut rows = Vec::new();
    for cores in &opts.cores_sweep {
        let row = measure_row(rig, opts, *cores);
        print_row(&row);
        rows.push(row);
    }
    write_report(opts, &rows);
}
