// SPDX-License-Identifier: Apache-2.0
//! The JSON report the orchestrator reads.

use serde_json::json;
use serde_json::Value;

use super::args::Args;
use super::client::Totals;
use super::client::Window;

/// The `p`-quantile of an ascending latency list, `0` when empty.
fn quantile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

pub(super) fn report(a: &Args, totals: &Totals, window: &Window, presign_secs: f64) -> Value {
    let lat = &totals.latencies_us;
    json!({
        "schema": "mcp-re-saturation-loadgen/v1",
        "id": a.id,
        "mode": a.mode,
        "connections": a.connections,
        "requests": a.requests,
        "successes": totals.successes,
        "failures": totals.failures,
        "handshakes": totals.handshakes,
        "wall_secs": window.elapsed_secs,
        "start_ms": window.start_ms,
        "end_ms": window.end_ms,
        "presign_secs": presign_secs,
        "throughput_rps": totals.successes as f64 / window.elapsed_secs,
        "latency_us": { "p50": quantile(lat, 0.50), "p99": quantile(lat, 0.99),
                        "p999": quantile(lat, 0.999),
                        "max": lat.last().copied().unwrap_or(0) },
        "first_error": totals.first_error,
    })
}
