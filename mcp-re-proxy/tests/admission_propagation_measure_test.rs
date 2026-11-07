// SPDX-License-Identifier: Apache-2.0
//! MCPRE-493 — MEASURE cross-replica admission-revocation propagation against the
//! declared P bound, over a real shared store.
//!
//! This is the fourth ADR-MCPRE-053 acceptance criterion, and the reason it stayed
//! open: the bound was declared, enforced and vector-tested, but nothing had ever
//! measured a real revocation reaching a replica that did not perform it.
//!
//! **What is measured, stated precisely.** Two `HttpProfileProxy` replicas share one
//! Redis-backed admission source and nothing else — separate delegated signers,
//! separate replay tiers, separate connections. An authority revokes a workload on a
//! THIRD connection. The measurement is the wall-clock interval from the revoking
//! write returning to the first request on the *other* replica being refused.
//!
//! **What that number is and is not.** It is the propagation delay of THIS mechanism:
//! an authoritative record read live per request. There is no cached copy, so the
//! delay is the store's own write-then-read visibility plus one round trip — not a
//! cache TTL, and not a push channel's delivery time. A deployment that adds a
//! bounded cache is making a different claim and must measure it separately;
//! `RevocationTier` exists so that difference cannot be quietly elided.
//!
//! It is also a LOCAL number. Measured against a Redis on the same host, it bounds
//! the mechanism, not a production fleet: a real deployment adds network RTT and
//! replication lag between the writer and each replica's reader. What this run
//! establishes is that the mechanism propagates at all, that it does so to a replica
//! with no prior knowledge of the workload, and what the floor looks like when the
//! store is not the bottleneck.
//!
//! Skipped without `MCP_RE_TEST_REDIS_URL` (hard-failed under
//! `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring `redis_trust_epoch_e2e_test.rs`.
#![cfg(feature = "redis_replay")]

#[path = "admission_propagation_measure_test/fixtures.rs"]
mod fixtures;
#[path = "admission_propagation_measure_test/fleet.rs"]
mod fleet;

use fleet::Fleet;

/// The P bound this run is measured against, in milliseconds.
///
/// Not a universal constant: it is what a deployment DECLARES as its propagation
/// budget, and the measurement's job is to say whether the mechanism meets the one
/// declared here. Generous on purpose — a floor test that fails on an unrelated
/// machine hiccup teaches nothing, and the interesting result is the observed number,
/// which the run prints.
const DECLARED_P_MS: u128 = 2_000;

fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable");
    }
    url
}

/// A per-run workload id, so concurrent runs never observe each other's revocation.
fn unique_workload() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("workload-propagation-{now}")
}

#[test]
fn a_revocation_reaches_a_sibling_replica_within_the_declared_p_bound() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP a_revocation_reaches_a_sibling_replica_within_the_declared_p_bound: \
             MCP_RE_TEST_REDIS_URL unset"
        );
        return;
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        let fleet = Fleet::start(&url, unique_workload()).await;
        fleet.assert_both_replicas_admit().await;

        let revoked_at = fleet.revoke().await;
        let propagation = fleet
            .poll_sibling_until_refused(revoked_at, DECLARED_P_MS)
            .await;

        // The number this test exists to produce. Printed rather than only asserted:
        // the pass/fail says the mechanism met a declared budget, the value says what
        // the budget could honestly be set to.
        println!(
            "MCPRE-493 propagation: revocation visible to a sibling replica in {}ms \
             ({} request(s)), against a declared P bound of {}ms. \
             Mechanism: live per-request read of the shared authoritative record — \
             no cached copy, so this is store visibility + one round trip, measured \
             against a LOCAL Redis. A production fleet adds network RTT and \
             replication lag.",
            propagation.elapsed.as_millis(),
            propagation.attempts,
            DECLARED_P_MS,
        );

        fleet.assert_the_revocation_holds_everywhere().await;
    });
}
