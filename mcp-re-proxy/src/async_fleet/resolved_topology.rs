// SPDX-License-Identifier: Apache-2.0
//! The serving shape this host gives a deployment's shard request, resolved once.
//!
//! [`ShardTopologyRequest`] is what the operator said, with "let the host decide" a
//! choice rather than a count. Turning that into shards and a pool depth reads the host's
//! CPU count, an environment reading, so it happens once, here, and everything that needs
//! the shard count takes this value: the inner plane sizing its bound against the fleet's
//! admission ceiling, and the fleet binding one listener per shard. Two readings of the
//! host could disagree; one value cannot.

use std::num::NonZeroUsize;

use crate::config_state::topology::ShardTopologyRequest;

use super::ShardDepth;

/// Pool depth a shard is given when the operator does not choose one, capped.
///
/// Depth past this bought nothing measurable and started costing: 8 workers/shard reached
/// 44,803 rps and 16 reached 46,325 (+3.4%) while scheduler latency rose from 60us to
/// 83us. The cap is where the curve flattens, not a hardware constant.
pub(super) const DEFAULT_MAX_WORKERS_PER_SHARD: usize = 8;

/// The number of serving shards and each shard's pool depth, as this host resolved them.
///
/// The fields are private and [`resolve`](Self::resolve) is the only producer outside
/// tests, so holding one means the host was asked exactly as the request directs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTopology {
    shards: NonZeroUsize,
    depth: ShardDepth,
}

impl ResolvedTopology {
    /// Resolve `request` on this host.
    ///
    /// The default is ONE SHARD PER CPU, each with a worker pool — shard count is NOT
    /// reduced to pay for depth.
    ///
    /// Both axes matter, for different reasons, and which one dominates depends on the
    /// WORKLOAD rather than the hardware:
    ///
    /// * **Shards parallelise `accept`.** Each shard owns its own `SO_REUSEPORT` listener,
    ///   and a single listener serialises connection establishment. On the cold-mTLS §7
    ///   envelope (every request a new connection + full handshake) this dominates
    ///   everything else: measured on an 8-vCPU GKE node at a constant 8 threads, 8 shards
    ///   x 1 worker reached 369.0 rps against 125.9 for 2 x 4 and 65.5 for 1 x 8 — 5.6x
    ///   across the same thread count.
    /// * **Depth parallelises polling.** A single-threaded shard has one thread driving the
    ///   I/O reactor AND polling every task, so with hundreds of concurrent futures a
    ///   readied task waits milliseconds. On a keepalive workload, where `accept` is
    ///   amortised, this dominates instead: 8 shards x 8 workers reached 44,803 rps against
    ///   10,362 for 8 x 1 on a 14-cpu host.
    ///
    /// Trading shards away for depth (`ceil(cpus/workers)` shards) resolves an 8-vCPU host
    /// to ONE shard, which measured 65.5 rps against 369.0 on the cold envelope. Keeping a
    /// shard per cpu and adding depth costs ~3% cold (369.0 -> 358.1) and gains ~4.3x
    /// keepalive, so it is the defensible default.
    ///
    /// A single-cpu host resolves to 1 x 1, the single-threaded shard.
    ///
    /// This remains a STARTING POINT, not a claim of optimality: cache domains, SMT,
    /// P/E-core asymmetry and epoll-vs-kqueue wakeups all move the optimum, and so does the
    /// connection profile. Measure a given host with `scripts/runtime_topology_sweep.sh`.
    pub fn resolve(request: ShardTopologyRequest) -> Self {
        let available = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        Self::resolve_on(request, available)
    }

    /// Resolve `request` against a host with `available` cpus.
    ///
    /// The depth comes back as a [`ShardDepth`], not a number: an explicit `1` and a
    /// single-cpu host's derived `1` are different facts, and the delegated-TLS refusal
    /// turns on the difference.
    fn resolve_on(request: ShardTopologyRequest, available: NonZeroUsize) -> Self {
        let shards = request.shards().unwrap_or(available);
        let depth = match request.workers_per_shard() {
            Some(stated) => ShardDepth::stated(stated.get()),
            None => ShardDepth::derived(DEFAULT_MAX_WORKERS_PER_SHARD.min(available.get())),
        };
        ResolvedTopology { shards, depth }
    }

    /// The number of serving shards, each with its own `SO_REUSEPORT` listener.
    pub fn shards(&self) -> NonZeroUsize {
        self.shards
    }

    /// Tokio worker threads inside each shard's runtime, and whose number it is.
    ///
    /// Depth parallelises POLLING; shards parallelise `accept`. Under delegated TLS custody
    /// the provenance decides between a startup refusal and a derived depth — the four
    /// cases are [`CorePool::for_core`](super::CorePool::for_core)'s.
    pub fn depth(&self) -> ShardDepth {
        self.depth
    }

    /// A topology with the given shape, for tests that drive the fleet without a host.
    #[cfg(test)]
    pub(crate) fn for_test(shards: usize, depth: ShardDepth) -> Self {
        ResolvedTopology {
            shards: NonZeroUsize::new(shards).expect("a test topology has at least one shard"),
            depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("a host has at least one cpu")
    }

    fn request(cores: usize, workers: usize) -> ShardTopologyRequest {
        let mut config = crate::config_state::test_support::legal_config();
        config.cores = cores;
        config.workers_per_shard = workers;
        crate::config_state::topology::classify(&config).1
    }

    fn shape(topology: ResolvedTopology) -> (usize, usize) {
        (topology.shards().get(), topology.depth().get())
    }

    /// Explicit configuration always wins over the host-derived default — an operator who
    /// measured their own hardware must not be second-guessed.
    #[test]
    fn explicit_topology_is_never_overridden() {
        let host = cpus(64);
        assert_eq!(
            ResolvedTopology::resolve_on(request(4, 4), host),
            ResolvedTopology::for_test(4, ShardDepth::stated(4))
        );
        assert_eq!(
            ResolvedTopology::resolve_on(request(1, 16), host),
            ResolvedTopology::for_test(1, ShardDepth::stated(16))
        );
        // An explicit 1 restores the single-threaded share-nothing shard, so it must
        // survive as 1 and not be auto-filled to the default depth.
        assert_eq!(
            ResolvedTopology::resolve_on(request(8, 1), host),
            ResolvedTopology::for_test(8, ShardDepth::stated(1))
        );
    }

    /// OWNER RULING 7, at the resolver: a configured depth comes back as the OPERATOR'S
    /// and an auto-filled one as the HOST'S, and the two stay distinguishable. This is the
    /// fact `CorePool::for_core` refuses on.
    #[test]
    fn a_resolved_depth_says_whether_the_operator_or_the_host_chose_it() {
        let stated = ResolvedTopology::resolve_on(request(0, 1), cpus(1)).depth();
        assert!(
            stated.is_operator_stated(),
            "--workers-per-shard 1 is a request, not a default"
        );
        let derived = ResolvedTopology::resolve_on(request(0, 0), cpus(1)).depth();
        assert!(
            !derived.is_operator_stated(),
            "an absent flag is the operator declining to choose"
        );
        assert_eq!(
            stated.get(),
            derived.get(),
            "the same number, different facts"
        );
    }

    /// The default keeps ONE SHARD PER CPU and adds depth on top; it never trades shards
    /// away for depth. At a constant 8 threads on an 8-vCPU node, 8x1 measured 369.0 rps
    /// against 65.5 for 1x8 on a cold-connection workload.
    #[test]
    fn auto_keeps_a_shard_per_cpu_and_adds_depth() {
        let auto = |n| shape(ResolvedTopology::resolve_on(request(0, 0), cpus(n)));
        assert_eq!(auto(64), (64, 8));
        assert_eq!(auto(14), (14, 8));
        assert_eq!(auto(8), (8, 8));
        assert_eq!(auto(4), (4, 4));
        // A single-cpu host gets exactly the single-threaded shard: a deployment that
        // cannot use a pool must not be handed one.
        assert_eq!(auto(1), (1, 1));
    }

    /// Auto is one listener per cpu, never a degenerate shape, and depth stays under the
    /// cap. Threads do exceed the cpu count once the host is wider than one worker; that is
    /// deliberate — parked pool threads cost ~3% cold and gained ~4.3x keepalive.
    #[test]
    fn auto_is_a_listener_per_cpu_with_a_capped_pool() {
        for n in 1..=64 {
            let (shards, depth) = shape(ResolvedTopology::resolve_on(request(0, 0), cpus(n)));
            assert_eq!(shards, n, "cpus={n}");
            assert!(
                (1..=DEFAULT_MAX_WORKERS_PER_SHARD).contains(&depth),
                "cpus={n}"
            );
        }
    }

    /// `resolve` is `resolve_on` with this host's cpu count, so the expectations above are
    /// about the policy and hold on whichever machine runs the suite.
    #[test]
    fn resolve_asks_this_host() {
        let available = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        for (cores, workers) in [(0, 0), (3, 0), (0, 2), (5, 6)] {
            assert_eq!(
                ResolvedTopology::resolve(request(cores, workers)),
                ResolvedTopology::resolve_on(request(cores, workers), available)
            );
        }
    }
}
