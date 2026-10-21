// SPDX-License-Identifier: Apache-2.0
//! The shared control runtime (ADR-MCPRE-056 §8): execution substrate, not a plane.
//!
//! Every networked control-plane client runs its background work here — the Redis replay
//! store's `ConnectionManager` reconnect task, the MRTR continuation store, the admission
//! source — on one process-lifetime runtime distinct from the per-core serving runtimes.
//!
//! # It does not know why it exists
//!
//! This module never inspects configuration. A capability needs the runtime exactly when
//! its owner selected a networked store — `ReplayPlan::store()` naming Redis,
//! `ContinuationControlPlan::shared()` naming a store, `AdmissionState::enforced()` naming
//! a gate — and that capability's networked arm asks [`ControlRuntimeProvision::handle`]
//! for access. The selection that needs the runtime and the request that obtains it are
//! the same step, so there is no separately computed requirement for a consumer to find
//! missing.
//!
//! The runtime used to be built from whichever seam happened to reach for it first, which
//! was the replay tier — and admission, whose Redis endpoint has nothing to do with replay,
//! was thereby made unimplementable on the CP/linearizable tier. An operator who supplied
//! `--admission-redis-url` was told the flag was missing, and the natural resolution was to
//! turn a security control off. Here every networked arm reaches the same provision, so no
//! capability's access depends on another having been selected.
//!
//! # Ownership vs. access
//!
//! [`ControlRuntime`] owns the runtime, and the provision owns the [`ControlRuntime`] once
//! one is started. Consumers get a `tokio::runtime::Handle`, which conveys execution
//! ACCESS and no ownership: a cloned handle does not keep the runtime alive, which is
//! exactly the lifetime property wanted here. A handle conveys no usable execution
//! guarantee once its owner is gone — after shutdown, I/O-dependent work on it can fail or
//! panic. It is access while the owner lives, not a way to resurrect it.
//!
//! # Shutdown order, for whoever owns this next
//!
//! An owner holding BOTH this runtime and resources bound to it must drain or drop those
//! resources BEFORE reclaiming the runtime. The Redis clients' reconnect machinery is
//! asynchronous and lives here; tearing the substrate down under a live consumer is a
//! lifecycle relationship nobody wrote down, which is the class of defect this refactor
//! exists to remove. Do not leave that to field-declaration order.

use std::sync::Mutex;
use std::sync::PoisonError;

/// The shared control runtime, started by the first networked arm that asks for it.
///
/// Held by the materializing runtime from the moment materialization begins, so a runtime
/// started part-way through is owned before the step that started it returns. A deployment
/// whose owners selected no networked store never asks, and starts no threads.
pub struct ControlRuntimeProvision {
    /// Locked across the build, so concurrent first requests start one runtime between them.
    runtime: Mutex<Option<ControlRuntime>>,
}

impl ControlRuntimeProvision {
    /// A provision nothing has asked yet.
    pub fn idle() -> ControlRuntimeProvision {
        ControlRuntimeProvision {
            runtime: Mutex::new(None),
        }
    }

    /// Execution access for a networked arm, starting the runtime on the first request.
    ///
    /// Every later request receives a handle to the same runtime. The only refusal is the
    /// runtime failing to build, which is a fact about the host.
    pub fn handle(&self) -> Result<tokio::runtime::Handle, String> {
        // A poisoned lock means another request panicked; the slot is still `None` or a
        // fully built runtime, because the build completes before it is stored.
        let mut slot = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(runtime) = slot.as_ref() {
            return Ok(runtime.handle());
        }
        let started = ControlRuntime::start()?;
        let handle = started.handle();
        *slot = Some(started);
        Ok(handle)
    }

    /// The runtime, if any arm asked for one — taken for reclamation in teardown order.
    pub fn take(&mut self) -> Option<ControlRuntime> {
        self.runtime
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The owned process-lifetime control runtime.
pub struct ControlRuntime {
    runtime: tokio::runtime::Runtime,
}

impl ControlRuntime {
    /// Build the runtime: one worker, named so it is identifiable in a thread dump.
    pub fn start() -> Result<ControlRuntime, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("mcp-re-control")
            .build()
            .map_err(|e| format!("build control runtime: {e}"))?;
        Ok(ControlRuntime { runtime })
    }

    /// Execution access for a consumer. Conveys no ownership: this handle will not keep
    /// the runtime alive, and is not usable once the owner is gone.
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn a_deployment_that_needs_no_control_plane_client_starts_no_runtime() {
        let mut idle = ControlRuntimeProvision::idle();
        assert!(
            idle.take().is_none(),
            "nothing asked for access, so nothing was built"
        );
    }

    /// The first request starts the runtime, and the provision owns what it started.
    #[test]
    fn the_first_request_starts_the_runtime_and_the_provision_owns_it() {
        let mut provision = ControlRuntimeProvision::idle();
        let handle = provision.handle().expect("the runtime builds");
        let owned = provision
            .take()
            .expect("a request for access started a runtime the provision owns");
        assert_eq!(handle.id(), owned.handle().id());
    }

    /// Several consumers share ONE substrate rather than each building its own, and none
    /// of them depends on another having asked first.
    #[test]
    fn every_consumer_receives_a_handle_to_the_same_runtime() {
        let provision = ControlRuntimeProvision::idle();
        let (admission, continuation, replay) = (
            provision.handle().expect("build"),
            provision.handle().expect("build"),
            provision.handle().expect("build"),
        );
        assert_eq!(replay.id(), continuation.id());
        assert_eq!(continuation.id(), admission.id());
    }

    /// Concurrent first requests share one runtime, and the provision owns it.
    #[test]
    fn concurrent_first_requests_share_the_one_runtime_the_provision_owns() {
        let mut provision = ControlRuntimeProvision::idle();
        let barrier = std::sync::Barrier::new(4);
        let ids: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        provision.handle().expect("build").id()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().expect("worker"))
                .collect()
        });
        let owned = provision
            .take()
            .expect("a runtime was started")
            .handle()
            .id();
        assert!(ids.iter().all(|id| *id == owned), "{ids:?} vs {owned:?}");
    }

    /// A handle conveys access, not ownership.
    ///
    /// The task is COOPERATIVE — it yields — because that is what the contract is about:
    /// dropping the runtime stops tasks at a yield point and drops their futures. A
    /// non-yielding or `spawn_blocking` task would instead be testing tokio's handling of
    /// uncooperative work, and could hang shutdown rather than assert anything.
    #[test]
    fn dropping_the_owner_stops_work_a_surviving_handle_had_started() {
        let started = Arc::new(AtomicBool::new(false));
        let still_running = Arc::new(AtomicBool::new(false));

        let rt = ControlRuntime::start().expect("build");
        let handle = rt.handle();

        let started_in_task = Arc::clone(&started);
        let running_in_task = Arc::clone(&still_running);
        handle.spawn(async move {
            started_in_task.store(true, Ordering::SeqCst);
            loop {
                // A yield point, so shutdown can reclaim this task.
                tokio::time::sleep(Duration::from_millis(5)).await;
                running_in_task.store(true, Ordering::SeqCst);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(started.load(Ordering::SeqCst), "the task never ran");

        drop(rt);

        // The handle outlived the runtime; it did not keep it alive.
        still_running.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !still_running.load(Ordering::SeqCst),
            "work continued after its execution substrate was reclaimed"
        );
        drop(handle);
    }

    /// Property 4, and NOT what the test above proves.
    ///
    /// That one shows a handle does not own the runtime. This one shows the OWNER does
    /// not escape a later failure: an implementation could kill tasks correctly on drop
    /// and still leak the runtime by stashing it somewhere that outlives the `?`.
    ///
    /// This is the third instance of one family — detached workers surviving a failed
    /// startup, a resolver surviving its refresh producer, a runtime surviving a later
    /// materialization failure. The law is that successful construction of an
    /// intermediate resource must not let its lifetime escape a later startup failure.
    #[test]
    fn a_runtime_built_before_a_later_failure_does_not_escape_it() {
        let alive = Arc::new(AtomicBool::new(false));

        // A materialization that gets the substrate up, starts control-plane work on
        // it, and then fails at a later phase — the shape of every `?` between the
        // first networked client and `serve_fleet`.
        fn materialize(alive: Arc<AtomicBool>) -> Result<(), String> {
            let control = ControlRuntime::start()?;
            control.handle().spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    alive.store(true, Ordering::SeqCst);
                }
            });
            std::thread::sleep(Duration::from_millis(50));
            Err("a later materialization phase failed".to_string())
        }

        assert!(materialize(Arc::clone(&alive)).is_err());
        assert!(
            alive.load(Ordering::SeqCst),
            "the control-plane work never started, so this proves nothing"
        );

        // Nothing holds the runtime now. If it had escaped, the task would still tick.
        alive.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !alive.load(Ordering::SeqCst),
            "control-plane activity survived the failed materialization that created it"
        );
    }
}
