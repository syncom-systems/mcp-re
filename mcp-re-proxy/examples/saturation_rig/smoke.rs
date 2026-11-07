// SPDX-License-Identifier: Apache-2.0
//! `--smoke`: the liveness assertion. It prints no throughput claim.

use std::time::Duration;

use super::generators::Load;
use super::rig::Rig;

/// The liveness parameters. Small enough to run on every pull request, large enough that
/// the backend's CPU is measurable rather than rounded away by `ps`.
const SMOKE_CONNECTIONS: usize = 8;
const SMOKE_REQUESTS: usize = 2000;

/// What is wrong with a smoke run, one entry per independent assertion that failed.
fn liveness_failures(failed: usize, rps: f64) -> Vec<String> {
    let mut bad = Vec::new();
    if failed > 0 {
        bad.push(format!(
            "{failed}/{SMOKE_REQUESTS} requests were refused, or answered without the \
             inner backend's echo — the reason is printed above as `generator error:` \
             and carries the proxy's wire code"
        ));
    }
    if rps <= 0.0 {
        bad.push("no request completed at all".to_string());
    }
    bad
}

fn report_liveness_failure(bad: &[String]) {
    eprintln!("\nsaturation rig LIVENESS FAILED:");
    for b in bad {
        eprintln!("  * {b}");
    }
    eprintln!(
        "\nThe instrument, not necessarily the proxy, is what this proves broken: the rig \n\
         builds its own fixtures and signs its own corpus, so a serving-path change that \n\
         moves an admission operand leaves it refused at 100% while every other lane stays \n\
         green. Fix the rig to match the production request, never the proxy to accept the \n\
         rig's."
    );
}

/// Prove the instrument can still construct a request this proxy admits, and that a
/// positive request reaches the backend. Returns the process exit status.
///
/// The assertions are independent, and each has been the whole failure on its own: a
/// refused corpus shows up as failures, a generator that never started shows up as a zero
/// rate, and a reply the proxy produced WITHOUT dispatching shows up as a missing backend
/// echo — every 2xx in this mode must carry the inner server's echo of the request method.
pub(super) fn run_smoke(rig: &Rig) -> i32 {
    let headroom = (SMOKE_CONNECTIONS * 4).max(64);
    let (proxy, target) = rig.spawn_proxy(1, headroom);
    std::thread::sleep(Duration::from_millis(300));
    // Every generator this mode spawns must PROVE the reply came from the inner backend,
    // not merely that it was a 2xx. Inherited by the children; never set on a measured run.
    std::env::set_var("MCP_RE_SAT_REQUIRE_ECHO", "1");
    let b0 = rig.backend_cpu();
    let load = Load {
        connections: SMOKE_CONNECTIONS,
        requests: SMOKE_REQUESTS,
        mode: "keepalive",
    };
    let measured = rig.generate(&target, 1, &load);
    let b1 = rig.backend_cpu();
    drop(proxy);

    let backend_cpu = b1 - b0;
    // backend_cpu is REPORTED, never asserted on: `ps -o time=` resolves centiseconds on
    // macOS and whole seconds on Linux, so a healthy sub-second backend reads 0.00 there.
    // Dispatch is proven by the backend's echo in every reply instead.
    println!(
        "smoke: attempted={SMOKE_REQUESTS} failures={} rate={:.0}/s \
         backend_cpu={backend_cpu:.2}s (reported, not asserted)",
        measured.failed, measured.rps
    );
    let bad = liveness_failures(measured.failed, measured.rps);
    if bad.is_empty() {
        println!("smoke: PASS — the saturation instrument constructs a request this proxy serves.");
        return 0;
    }
    report_liveness_failure(&bad);
    1
}
