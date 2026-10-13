// SPDX-License-Identifier: Apache-2.0
//! WHICH tokio runtime one serving core gets, and how much blocking handshake work it may
//! admit onto it.
//!
//! One current-thread runtime per core is the share-nothing default (ADR-MCPRE-051 §1): no
//! work stealing, no cross-core hot-path state. Delegated TLS custody breaks the assumption
//! that runtime holds, so the choice is a decision with a security consequence rather than
//! a tuning knob, and it is made here where the reasoning can be stated once.
//!
//! The pool depth and the handshake bound are ONE decision, not two. A pool is not a bound:
//! a peer needs only as many concurrent connections as there are workers to occupy every
//! one of them, and TLS 1.3 signs `CertificateVerify` before the client's `Certificate` is
//! ever seen, so it needs no credential to do it. Sizing the bound from a constant while
//! the depth came from somewhere else is how the two stopped agreeing; [`CorePool`] is the
//! one place both are decided, from the same inputs, and [`CorePool::handshake_bound`] is
//! the only way to obtain the bound.
//!
//! Building the runtime is FALLIBLE and the failure is reported: `build` allocates threads
//! and an event loop, so a core the operating system declines must not leave the fleet
//! reporting a successful bind with one fewer server behind it.

use std::num::NonZeroUsize;

use crate::config_state::PrivateKeyExposure;

/// Worker threads a core is given when the TLS handshake signature can block and the
/// resolved depth is a single worker.
///
/// Sized so a handful of concurrent stalled handshakes still leaves the core serving.
/// It is not a throughput knob: on the exported-key path the runtime stays
/// single-threaded, and raising this would not make a wedged token any less wedged —
/// it only widens the window before the pool is exhausted.
const DELEGATED_TLS_WORKERS_PER_CORE: usize = 4;

/// The most concurrent blocking handshake signatures ANY core admits — a CEILING on
/// [`CorePool::handshake_bound`], never the bound itself.
///
/// The bound is `depth - 1`, so that a core under a full handshake flood always retains a
/// worker for its accept loop, its established connections and its in-flight requests. This
/// caps that expression from above so a wide pool does not silently raise how much blocking
/// KMS or PKCS#11 work one core will carry at once: widening it is a throughput change with
/// its own argument to make, not a consequence of the operator choosing more workers.
/// Raising it re-opens exactly what the bound closes.
const DELEGATED_TLS_HANDSHAKES_PER_CORE: usize = 2;

/// How many TLS handshakes one core may have signing at once, where that signature is a
/// device or KMS round trip that occupies its worker thread outright.
///
/// [`CorePool::handshake_bound`] is the sole producer: there is no constructor, no
/// conversion and no public field, so a bound cannot be named independently of the pool
/// whose depth it must stay below. That is the property — holding one of these means it
/// was derived from a runtime that was actually built with room to spare.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeBound(Option<usize>);

impl HandshakeBound {
    /// Permits for this core's handshake semaphore; `None` where the signature is in-memory
    /// and cannot block, and bounding it would cost throughput for nothing.
    pub(crate) fn permits(self) -> Option<usize> {
        self.0
    }
}

/// One serving core's runtime shape, and what that shape lets the core admit.
///
/// The representation is private and there is exactly one producer,
/// [`CorePool::for_core`]. Downstream gets a runtime built to the shape (`build_runtime`)
/// and the handshake bound that shape supports ([`CorePool::handshake_bound`]). Nothing
/// projects the two as one destructurable record, so no consumer can pair a bound with a
/// depth that did not produce it.
pub struct CorePool {
    /// Worker threads this core's runtime gets; `None` is the share-nothing current-thread
    /// runtime, which has no pool to bound anything against.
    workers: Option<usize>,
    /// Concurrent blocking handshake signatures this core admits; `None` wherever the
    /// handshake signature cannot block.
    handshakes: Option<usize>,
}

impl CorePool {
    /// Decide one core's pool and its handshake bound together.
    ///
    /// DELEGATED TLS custody is why a pool exists at all. The handshake signature is
    /// produced by rustls' SYNCHRONOUS `Signer::sign`, which on that path is a blocking KMS
    /// round trip or a PKCS#11 `C_Sign`. On a current-thread runtime one such call freezes
    /// the core outright — its accept loop, its keep-alive connections and every in-flight
    /// signed request — for the duration, and no timer can preempt it because the future
    /// never yields. Any peer opening connections triggers it, so it is a
    /// trivially-reachable DoS.
    ///
    /// Those deployments get a small worker pool per core, so a stalled signature costs one
    /// worker rather than a whole core, AND a bound strictly below that pool, so a flood
    /// cannot occupy every worker in it. The bound is `depth - 1` capped at
    /// `DELEGATED_TLS_HANDSHAKES_PER_CORE`, which is what makes it a function of the depth
    /// this core was actually built with rather than of a constant that never saw the depth:
    /// a two-worker core admits one handshake, not two.
    ///
    /// THREE CASES:
    ///
    /// | custody | depth | outcome |
    /// |---|---|---|
    /// | exported key | 1 | the share-nothing current-thread runtime |
    /// | delegated | 1 | the safe depth: `DELEGATED_TLS_WORKERS_PER_CORE` |
    /// | either | >= 2 | honoured exactly, and under delegated custody the bound follows it |
    ///
    /// A blocking signature is never served on a current-thread runtime, whatever depth
    /// arrives. An OPERATOR who stated a single worker under delegated custody never reaches
    /// this function: layer A refuses that pair (relation X10 in
    /// [`crate::config_state::cross_machine`]), because serving it as asked exposes the
    /// starvation and widening it serves a topology the operator was explicit about not
    /// wanting. A depth of 1 that does arrive here under delegated custody is the host's
    /// answer to `auto`, and raising it fills in for a number nobody chose.
    ///
    /// The share-nothing default is unchanged for the exported-key path, where signing is
    /// in-memory and never blocks. A configured pool depth gives the shard a work-stealing
    /// runtime; see [`ResolvedTopology::resolve`](super::ResolvedTopology::resolve) for why
    /// depth and shard count are both kept.
    ///
    /// The custody is the served snapshot's
    /// ([`ServerConfigSnapshot::key_exposure`](crate::config_snapshot::ServerConfigSnapshot::key_exposure)),
    /// so the shape is decided by the key the handshakes will actually sign with.
    pub fn for_core(workers_per_shard: NonZeroUsize, key_exposure: PrivateKeyExposure) -> Self {
        let tls_signing_may_block = key_exposure == PrivateKeyExposure::NonExporting;
        let workers = if workers_per_shard.get() > 1 {
            Some(workers_per_shard.get())
        } else if tls_signing_may_block {
            Some(DELEGATED_TLS_WORKERS_PER_CORE)
        } else {
            None
        };
        // `saturating_sub` is the honest algebra AND the true one: the leftover worker is
        // what is being computed, and on this arm `depth >= 2` (a resolved depth reaches it
        // only when it exceeds 1, and the override is 4), so nothing saturates.
        let handshakes = match workers {
            Some(depth) if tls_signing_may_block => Some(
                depth
                    .saturating_sub(1)
                    .min(DELEGATED_TLS_HANDSHAKES_PER_CORE),
            ),
            _ => None,
        };
        CorePool {
            workers,
            handshakes,
        }
    }

    /// The startup line for a core shaped around a blocking handshake signer; `None` where
    /// the signature is in-memory and the core runs the share-nothing default.
    pub(super) fn startup_line(&self) -> Option<String> {
        let workers = self.workers?;
        let handshakes = self.handshakes?;
        Some(format!(
            "mcp-re-proxy: TLS custody = DELEGATED: the handshake signature is a blocking \
             KMS/PKCS#11 call inside rustls' synchronous signer, so each core serves on a \
             pool of {workers} workers admitting {handshakes} concurrent handshake \
             signature(s) rather than the single-threaded share-nothing default. A stalled \
             signer then costs one worker instead of a whole core."
        ))
    }

    /// The pool depth this core runs; `None` for the share-nothing current-thread runtime.
    ///
    /// Nothing in production needs the depth back — `build_runtime` is the only consumer of
    /// it and it holds the value already — so this exists at the narrowest level that lets
    /// its one legitimate consumer work: the crate's controls, which need both halves of
    /// the depth/bound relation nameable for that relation to be assertable at all.
    #[cfg(test)]
    pub(crate) fn worker_threads(&self) -> Option<usize> {
        self.workers
    }

    /// How many blocking handshake signatures this core admits at once.
    pub fn handshake_bound(&self) -> HandshakeBound {
        HandshakeBound(self.handshakes)
    }

    /// Build this core's tokio runtime.
    ///
    /// Class R: `build` allocates threads and an event loop, so the failure is the caller's
    /// to report — a core the OS declines must not leave the fleet reporting a successful
    /// bind with one fewer server behind it.
    pub(super) fn build_runtime(
        &self,
        core_index: usize,
    ) -> std::io::Result<tokio::runtime::Runtime> {
        match self.workers {
            Some(threads) => tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .thread_name(format!("mcp-re-serve-{core_index}-w"))
                .enable_all()
                .build(),
            None => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custody(may_block: bool) -> PrivateKeyExposure {
        if may_block {
            PrivateKeyExposure::NonExporting
        } else {
            PrivateKeyExposure::ProcessReadable
        }
    }

    fn depth(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("a test depth is at least one worker")
    }

    fn pool(workers: usize, may_block: bool) -> CorePool {
        CorePool::for_core(depth(workers), custody(may_block))
    }

    // ------------------------------------------------------------------
    // The three cases, one control each.
    // ------------------------------------------------------------------

    /// CASE 1 — exported key on one worker. The signature is in-memory, so there is nothing
    /// to protect the core from: it gets the share-nothing current-thread runtime.
    #[test]
    fn a_share_nothing_core_has_no_pool_and_no_handshake_bound() {
        let pool = pool(1, false);
        assert_eq!(pool.worker_threads(), None);
        assert_eq!(pool.handshake_bound().permits(), None);
        assert_eq!(pool.startup_line(), None);
    }

    /// CASE 2 — delegated custody on one worker. A blocking signature on a current-thread
    /// runtime freezes the core, so the safe depth is used. Only a host-derived 1 reaches
    /// this case in production — an operator-stated 1 under delegated custody is refused
    /// at configuration — and a single-cpu host derives exactly that.
    #[test]
    fn delegated_custody_on_one_worker_gets_the_safe_depth() {
        let pool = pool(1, true);
        assert_eq!(pool.worker_threads(), Some(DELEGATED_TLS_WORKERS_PER_CORE));
        assert!(pool.handshake_bound().permits().is_some());
    }

    /// CASE 3 — delegated custody + a depth of 2 or more. Honoured EXACTLY, and the
    /// handshake admission is derived from that depth rather than from a constant.
    ///
    /// R12-648 is the defect inside this case: a two-worker core admitted two concurrent
    /// blocking handshakes, occupying both workers with connections that need no client
    /// credential. A constant cannot see the depth, so it cannot leave a worker spare.
    #[test]
    fn the_bound_follows_the_built_depth_and_is_capped_by_the_ceiling() {
        for workers in 2..=64 {
            let pool = pool(workers, true);
            assert_eq!(
                pool.worker_threads(),
                Some(workers),
                "a resolved depth of two or more is used as resolved"
            );
            let permits = pool
                .handshake_bound()
                .permits()
                .expect("a blocking signature is always bounded");
            assert!(
                permits < workers,
                "workers={workers}: {permits} handshakes on {workers} workers leaves none \
                 for the accept loop"
            );
            assert!(
                permits >= 1,
                "workers={workers}: a bound of zero refuses everything"
            );
        }
        // The ceiling, from both sides: two workers admit ONE, and past the ceiling the
        // bound stops rising — more workers is not more blocking work.
        assert_eq!(pool(2, true).handshake_bound().permits(), Some(1));
        assert_eq!(
            pool(3, true).handshake_bound().permits(),
            Some(DELEGATED_TLS_HANDSHAKES_PER_CORE)
        );
        assert_eq!(
            pool(64, true).handshake_bound().permits(),
            Some(DELEGATED_TLS_HANDSHAKES_PER_CORE)
        );
    }

    // ------------------------------------------------------------------
    // The custody axis, independent of the depth axis.
    // ------------------------------------------------------------------

    /// A pool the operator asked for is not a delegated-TLS pool. Bounding handshakes there
    /// would cost throughput to defend against a signature that cannot block.
    #[test]
    fn a_pool_without_delegated_tls_bounds_no_handshakes() {
        let pool = pool(8, false);
        assert_eq!(pool.worker_threads(), Some(8));
        assert_eq!(pool.handshake_bound().permits(), None);
    }

    /// A delegated-TLS core always gets a pool and always gets a bound, at every depth —
    /// an override that failed to fire would leave a current-thread runtime one signature
    /// can freeze, and a pool without a bound is not a bound.
    #[test]
    fn a_delegated_tls_core_is_always_pooled_and_always_bounded() {
        for workers in 1..=16 {
            let pool = pool(workers, true);
            assert!(
                pool.worker_threads().is_some(),
                "{workers}: a blocking signature on a current-thread runtime freezes the core"
            );
            assert!(
                pool.handshake_bound().permits().is_some(),
                "{workers}: a pool without a bound is not a bound"
            );
        }
    }

    /// The fleet's startup line states the shape it built: the pool and the bound it was
    /// actually given, not a restatement of the rule that chose them.
    #[test]
    fn the_startup_line_names_the_built_pool_and_bound() {
        let line = pool(3, true)
            .startup_line()
            .expect("a delegated-TLS core announces its pool");
        assert!(line.contains("DELEGATED"), "{line}");
        assert!(line.contains("pool of 3 workers"), "{line}");
        assert!(line.contains("admitting 2 concurrent"), "{line}");
        assert_eq!(pool(8, false).startup_line(), None);
    }
}
