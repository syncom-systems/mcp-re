// SPDX-License-Identifier: Apache-2.0
//! The generator tier: M load-generator processes against the proxy, and the aggregate of
//! their reports.

use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::Value;

use super::material::tmp;
use super::material::Material;
use super::proc::sample_cpu;

/// The offered load of one generator process.
pub(super) struct Load<'a> {
    pub(super) connections: usize,
    pub(super) requests: usize,
    pub(super) mode: &'a str,
}

/// The aggregate of one measurement.
pub(super) struct Measurement {
    pub(super) rps: f64,
    pub(super) p50: u64,
    pub(super) failed: usize,
    pub(super) cpu: f64,
}

/// What the generators' reports add up to.
struct Tally {
    ok: usize,
    failed: usize,
    p50: u64,
    first_start: u64,
    last_end: u64,
}

impl Tally {
    fn new() -> Self {
        Tally {
            ok: 0,
            failed: 0,
            p50: 0,
            first_start: u64::MAX,
            last_end: 0,
        }
    }

    fn absorb(&mut self, report: &Value) {
        self.ok += report["successes"].as_u64().unwrap_or(0) as usize;
        self.first_start = self
            .first_start
            .min(report["start_ms"].as_u64().unwrap_or(u64::MAX));
        self.last_end = self.last_end.max(report["end_ms"].as_u64().unwrap_or(0));
        self.failed += report["failures"].as_u64().unwrap_or(0) as usize;
        self.p50 = self
            .p50
            .max(report["latency_us"]["p50"].as_u64().unwrap_or(0));
    }

    /// TRUE aggregate: all successes over the union of the generators' windows.
    fn rps(&self) -> f64 {
        let span = (self.last_end.saturating_sub(self.first_start)) as f64 / 1000.0;
        if span > 0.0 {
            self.ok as f64 / span
        } else {
            0.0
        }
    }
}

/// One measurement's fixed inputs: which executable, against which target, at what load.
pub(super) struct Fleet<'a> {
    pub(super) exe: &'a str,
    pub(super) material: &'a Material,
    pub(super) target: &'a str,
    pub(super) load: &'a Load<'a>,
}

impl Fleet<'_> {
    fn spawn(&self, id: usize) -> (Child, PathBuf) {
        let (m, load) = (self.material, self.load);
        let out = tmp(&format!("gen{id}.json"));
        let child = Command::new(self.exe)
            .args([
                "--target",
                self.target,
                "--connections",
                &load.connections.to_string(),
                "--requests",
                &load.requests.to_string(),
                "--mode",
                load.mode,
                "--client-cert",
                &m.client_leaf_der.to_string_lossy(),
                "--client-key",
                &m.client_key_der.to_string_lossy(),
                "--server-ca",
                &m.server_ca_der.to_string_lossy(),
                "--id",
                &format!("g{id}"),
                "--out",
                &out.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn generator");
        (child, out)
    }

    /// One measurement: M generator processes against the proxy, aggregated.
    pub(super) fn run(&self, generators: usize) -> Measurement {
        let (kids, outs): (Vec<Child>, Vec<PathBuf>) =
            (0..generators).map(|g| self.spawn(g)).unzip();
        let cpu = wait_sampled(kids);
        let tally = collect_reports(&outs);
        Measurement {
            rps: tally.rps(),
            p50: tally.p50,
            failed: tally.failed,
            cpu,
        }
    }
}

/// Wait for every generator, sampling their CPU while they run; a dead process reports
/// nothing. Returns the summed peak CPU.
fn wait_sampled(kids: Vec<Child>) -> f64 {
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = sample_cpu(kids.iter().map(|k| k.id()).collect(), Arc::clone(&stop));
    for mut k in kids {
        let _ = k.wait();
    }
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap_or(0.0)
}

fn collect_reports(outs: &[PathBuf]) -> Tally {
    let mut tally = Tally::new();
    for o in outs {
        let Ok(text) = std::fs::read_to_string(o) else {
            continue;
        };
        let v: Value = serde_json::from_str(&text).expect("gen report");
        tally.absorb(&v);
        if let Some(e) = v["first_error"].as_str() {
            // Surfaced immediately: a rig that prints "N failures" and swallows the
            // reason is the thing that wasted the afternoon.
            eprintln!("  generator error: {e}");
        }
        let _ = std::fs::remove_file(o);
    }
    tally
}
