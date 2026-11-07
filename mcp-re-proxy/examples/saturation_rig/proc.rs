// SPDX-License-Identifier: Apache-2.0
//! Child-process plumbing: lifetime, CPU sampling, the backend tier and runfile lookup.

use std::io::BufRead;
use std::io::BufReader;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// A child that is killed when the rig drops, so a panic mid-sweep cannot leave a proxy
/// or a backend holding a port.
pub(super) struct Proc(Child);

impl Proc {
    pub(super) fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Under a profiling wrapper the direct child is the profiler, and SIGKILL
        // discards the capture it has not written yet. SIGTERM the grandchild instead.
        if std::env::var("MCP_RE_PROFILE_WRAPPER").is_ok() {
            let _ = Command::new("pkill")
                .args(["-TERM", "-P", &self.0.id().to_string()])
                .status();
            let _ = self.0.wait();
            return;
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wrap an already-spawned child so it is killed when the rig drops.
pub(super) fn guard(child: Child) -> Proc {
    Proc(child)
}

/// Total CPU-seconds a process has consumed, via `ps`. Sampled before and after a run so
/// each tier's share is reported rather than assumed.
pub(super) fn cpu_secs(pid: u32) -> f64 {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output();
    let Ok(out) = out else { return 0.0 };
    parse_cpu_time(String::from_utf8_lossy(&out.stdout).trim())
}

/// Parse `ps -o time=` output; formats are `MM:SS.ss` and `HH:MM:SS`.
fn parse_cpu_time(text: &str) -> f64 {
    let parts: Vec<f64> = text
        .split(':')
        .filter_map(|p| p.trim().parse::<f64>().ok())
        .collect();
    match parts.len() {
        2 => parts[0] * 60.0 + parts[1],
        3 => parts[0] * 3600.0 + parts[1] * 60.0 + parts[2],
        _ => 0.0,
    }
}

/// Poll a set of PIDs until `stop` is set, keeping the highest CPU reading seen for
/// each. Sampling AFTER a short-lived child exits returns nothing — `ps` cannot report a
/// process that is gone — which is why the first version of this reported 0.0 for every
/// generator and could not rule the client out.
pub(super) fn sample_cpu(pids: Vec<u32>, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<f64> {
    std::thread::spawn(move || {
        let mut peak = vec![0.0f64; pids.len()];
        while !stop.load(Ordering::Relaxed) {
            for (i, pid) in pids.iter().enumerate() {
                let c = cpu_secs(*pid);
                if c > peak[i] {
                    peak[i] = c;
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        peak.iter().sum()
    })
}

pub(super) fn spawn_backend(exe: &str, workers: usize) -> (Proc, String) {
    let mut child = Command::new(exe)
        .args(["--workers", &workers.to_string(), "--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn backend");
    let stdout = child.stdout.take().expect("backend stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("backend addr line");
    let addr = line
        .rsplit(' ')
        .next()
        .expect("addr token")
        .trim()
        .to_string();
    (Proc(child), addr)
}

/// Resolve a Bazel `data` dependency whose runfiles path the target's `env` names.
pub(super) fn runfile(env_key: &str) -> String {
    let rel = std::env::var(env_key)
        .unwrap_or_else(|_| panic!("{env_key} is not set — run the rig as a Bazel target"));
    let root = std::env::var("RUNFILES_DIR").unwrap_or_else(|_| {
        let exe = std::env::current_exe().expect("current_exe");
        format!("{}.runfiles", exe.display())
    });
    let path = std::path::Path::new(&root).join(&rel);
    assert!(
        path.exists(),
        "runfile {} ({env_key}) is missing",
        path.display()
    );
    path.display().to_string()
}
