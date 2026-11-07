// SPDX-License-Identifier: Apache-2.0
//! Async load generator for the saturation rig.
//!
//! SEPARATE from `tls_load_harness_bench` on purpose. That harness is the
//! ADR-MCPRE-051 §7 regression detector and every historical anchor was measured with
//! it; changing its client would make those numbers incomparable. This one answers a
//! different question — how fast can the proxy actually go — and its numbers are NOT
//! comparable to the §7 anchor.
//!
//! Three things the §7 client does that make it unable to saturate a fast proxy, and
//! that this one does not:
//!
//! 1. **One OS thread per connection.** At 1024 connections that is 1024 threads on a
//!    14-core box, so the client spends its time context-switching. Here each connection
//!    is a tokio task over a small worker pool.
//! 2. **Ed25519 signing on the hot path.** The §7 anchor notes client-side crypto costs
//!    as much as server-side, so a co-located client taxes the measurement twice. Here
//!    the corpus is signed BEFORE the clock starts and replayed from memory.
//! 3. **No remote target.** It spawns its own proxy, which is why every run so far has
//!    been co-located. This one drives `--target`.
//!
//! Nonces must stay unique or the replay tier rejects the request, so the corpus is
//! sized to the request count and each entry carries its own.

#[path = "saturation_loadgen/args.rs"]
mod args;
#[path = "saturation_loadgen/client.rs"]
mod client;
#[path = "saturation_loadgen/corpus.rs"]
mod corpus;
#[path = "saturation_loadgen/report.rs"]
mod report;
#[path = "saturation_loadgen/response.rs"]
mod response;

use std::time::Instant;

fn main() {
    let a = args::args();

    // PRE-SIGN. Every Ed25519 signature happens here, before the clock starts, so the
    // measured window contains no client-side asymmetric crypto.
    let sign_started = Instant::now();
    let corpus = corpus::build(&a);
    let presign_secs = sign_started.elapsed().as_secs_f64();

    let shared = client::Shared::new(&a, corpus);
    let window = client::drive(&shared, a.connections);

    let report = report::report(&a, &shared.totals(), &window, presign_secs);
    let text = serde_json::to_string_pretty(&report).expect("json");
    if let Some(path) = a.out {
        std::fs::write(path, &text).expect("write report");
    }
    println!("{text}");
}
