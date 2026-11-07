// SPDX-License-Identifier: Apache-2.0
//! The rig's command line and the two environment variables that complete it.

use std::fmt::Debug;
use std::str::FromStr;

pub(super) struct Options {
    pub(super) cores_sweep: Vec<usize>,
    pub(super) generators: usize,
    pub(super) connections: usize,
    pub(super) requests: usize,
    pub(super) mode: String,
    pub(super) backend_workers: usize,
    /// Escalation bound.
    pub(super) max_generators: usize,
    /// The gain below which one more generator is judged to have bought nothing.
    pub(super) saturation_pct: f64,
    /// Escalation proves saturation but leaves each row at a different offered load, so
    /// the core sweep stops being a curve. `--fixed-generators` pins every point to one
    /// count; the M/M+1 probe still runs so a row that is client-bound is still flagged.
    pub(super) fixed_generators: Option<usize>,
    /// The liveness mode. Not a measurement: it asserts that the instrument still works
    /// and reports no throughput, so it can run on the merge path without claiming one.
    pub(super) smoke: bool,
    pub(super) tier: String,
    pub(super) redis: String,
}

fn number<T: FromStr>(text: String, what: &str) -> T
where
    T::Err: Debug,
{
    text.parse().expect(what)
}

impl Options {
    pub(super) fn from_env_and_args() -> Self {
        // Must match the replica count actually running: `redis-wait-quorum` requires a
        // POSITIVE quorum, so a lone Redis cannot serve this rig at all. The default matches
        // the §7 lane, so the admission path measured here is the one the gate runs.
        let tier = std::env::var("MCP_RE_SAT_REPLAY_TIER")
            .unwrap_or_else(|_| "redis-wait-quorum:2:2000".to_string());
        let redis = std::env::var("MCP_RE_SAT_REDIS_URL").expect(
            "MCP_RE_SAT_REDIS_URL is required (the per-core plane refuses node-local replay)",
        );
        let mut options = Options {
            cores_sweep: vec![1, 2, 4, 8],
            generators: 2,
            connections: 256,
            requests: 40000,
            mode: "keepalive".to_string(),
            backend_workers: 6,
            max_generators: 8,
            saturation_pct: 5.0,
            fixed_generators: None,
            smoke: false,
            tier,
            redis,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            options.apply_flag(&flag, &mut || it.next().expect("flag needs a value"));
        }
        options
    }

    fn apply_flag(&mut self, flag: &str, val: &mut dyn FnMut() -> String) {
        if flag == "--smoke" {
            self.smoke = true;
        } else if !self.apply_load_flag(flag, val) && !self.apply_escalation_flag(flag, val) {
            panic!("unknown flag {flag}");
        }
    }

    /// The flags that shape one run's offered load. False when `flag` is not one of them.
    fn apply_load_flag(&mut self, flag: &str, val: &mut dyn FnMut() -> String) -> bool {
        match flag {
            "--cores" => {
                self.cores_sweep = val()
                    .split(',')
                    .map(|s| s.parse().expect("cores"))
                    .collect()
            }
            "--generators" => self.generators = number(val(), "generators"),
            "--connections" => self.connections = number(val(), "connections"),
            "--requests" => self.requests = number(val(), "requests"),
            "--mode" => self.mode = val(),
            "--backend-workers" => self.backend_workers = number(val(), "backend workers"),
            _ => return false,
        }
        true
    }

    /// The flags that bound the generator escalation. False when `flag` is not one of them.
    fn apply_escalation_flag(&mut self, flag: &str, val: &mut dyn FnMut() -> String) -> bool {
        match flag {
            "--max-generators" => self.max_generators = number(val(), "max generators"),
            "--saturation-pct" => self.saturation_pct = number(val(), "saturation pct"),
            "--fixed-generators" => self.fixed_generators = Some(number(val(), "fixed generators")),
            _ => return false,
        }
        true
    }
}
