// SPDX-License-Identifier: Apache-2.0
//! Keeping a delegated key in force (ADR-MCPRE-052 §6–§7).
//!
//! One loop, three things it reacts to, and they are not equally urgent:
//!
//! * the **schedule** — mint the successor while the predecessor is still valid, which is
//!   what the overlap window is for;
//! * a **trust-epoch advance**, which takes PRIORITY over the schedule: swapping now is
//!   what makes cross-replica revocation take effect on the next request rather than at
//!   the end of a full TTL;
//! * a **failure**, which never extends anything. Serving continues on the current key
//!   until its `exp` and then FAILS CLOSED — no stale-key extension, no direct-root
//!   fallback.
//!
//! Two failure modes are easy to mistake for success and are treated as failures here.
//! `ensure_active` reports `Ok(())` when successor issuance failed but the current key is
//! still valid — the PRIMARY failure mode, a root outage during the overlap window, exactly
//! what the overlap exists to absorb — and taking it as success would reset the backoff,
//! collapse the wake time to now, and re-enter immediately: a tight retry loop against the
//! root KMS/HSM, minting a fresh keypair every pass, for the whole overlap window. And an
//! unreadable or regressed shared epoch is refused for MINTING, because a credential
//! without a comparable epoch is unrevokable.

use std::sync::Arc;

use super::mint_successor::attempt_rotation;
use super::mint_successor::RotationStep;
use super::trust_epoch_advance::observe_trust_epoch;
use super::trust_epoch_advance::EpochStep;
use super::DelegatedEpochWatch;
pub(super) use failed_attempt::FailedAttempt;
use wait::wait_for_window;
pub(super) use wait::RotationScope;

mod failed_attempt;
mod wait;

/// The cold-path delegated-key rotation thread (ADR-MCPRE-052 §4/§6, ADR-MCPRE-051 §5): a
/// single owner drives the rotor OFF the per-core serving runtimes, so the root issuer's
/// blocking KMS/HSM calls never touch the request path. It mints a successor within the
/// overlap window before the current key's `exp` and republishes the hot-path snapshot; if
/// issuance fails while the current key is valid, serving continues until that `exp` and
/// THEN fails closed — never a stale-key extension or a direct-root fallback. The thread
/// observes its halt between naps so it exits promptly on a rolling deploy.
pub(super) fn spawn_delegated_rotation_task(
    workers: &mut crate::managed_worker::WorkerSet,
    mut rotor: crate::delegated_wiring::ProdDelegatedRotor,
    overlap: i64,
    epoch_watch: Option<DelegatedEpochWatch>,
) -> Result<(), String> {
    let halt = workers.halt();
    let (signer, retirement) = (rotor.signer(), rotor.retirement());
    workers.spawn(
        "delegated key rotation",
        supervise_delegated_rotation(Arc::clone(&signer), retirement, move || {
            let scope = RotationScope {
                signer: &signer,
                overlap,
                epoch_watch: epoch_watch.as_ref(),
                halt: &halt,
            };
            rotation_loop(&mut rotor, &scope);
        }),
    )
}

/// The `catch_unwind` and the fail-closed action it converts a panic into, AS A VALUE.
///
/// Taking the body as a value is what makes the supervisor reachable from a test: a panic
/// injected through `WorkerSet` directly measures `WorkerSet`, not this. It decides nothing
/// and stays private to this module.
///
/// SUPERVISION (C040). This thread is the ONLY thing that mints delegated keys, and nothing
/// observes it while it runs — `WorkerSet` reclaims it at shutdown, far too late to matter.
/// Left bare, a panic on any reachable `.expect()` (the CSPRNG draw, the two custody
/// invariants) would end all rotation for the process lifetime while every health surface
/// still read steady state: `DelegatedRotationMetrics.consecutive_failures` is only written
/// BY this thread, so a dead thread leaves it at 0 and the replica appears healthy right up
/// until the current key's `exp`, then 503s with no attributable cause.
///
/// So a panic becomes the strongest honest signal available: RETIRE the snapshot, which
/// makes the hot path fail closed IMMEDIATELY (`delegated_signing_unavailable`) rather than
/// at `exp`, and record a failure so the metric stops reading healthy. The thread does not
/// resume — after a panic the rotor's state is not known good, and continuing to mint from
/// it would be worse than refusing. A CLEAN return retires too: the plane retires before
/// halting the worker, so this repeats it, but "once maintenance has stopped, no new
/// signature" then holds however the worker came to stop.
fn supervise_delegated_rotation(
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    retirement: crate::delegated_server_signer::SigningRetirement,
    body: impl FnOnce() + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    move || {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_ok() {
            retirement.retire_permanently();
            return;
        }
        retirement.retire_permanently();
        signer.metrics().record_failure();
        eprintln!(
            "mcp-re-proxy: FATAL: the delegated rotation thread PANICKED. Delegated key \
             rotation has stopped for the lifetime of this process and the current \
             snapshot has been retired, so response signing now fails closed \
             (delegated_signing_unavailable) immediately rather than at the key's exp. \
             This replica cannot recover on its own — restart it."
        );
    }
}

/// The rotation loop proper. Split out of [`spawn_delegated_rotation_task`] so the
/// supervisor above can catch a panic from anywhere inside it.
pub(super) fn rotation_loop(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    scope: &RotationScope<'_>,
) {
    // Failures since the last success drive the backoff schedule; 0 in steady state.
    let mut consecutive_failures: u32 = 0;
    // The epoch this node is currently minting under (starts at the configured baseline
    // label from the startup issuance). An advance of the shared counter moves it;
    // verifiers pinned to the old label then reject across replicas.
    let mut last_epoch = rotor.trust_epoch().clone();
    while let Some(failures) = rotation_pass(rotor, scope, &mut last_epoch, consecutive_failures) {
        consecutive_failures = failures;
    }
}

/// One pass of the loop: wait, observe the epoch, rotate. Returns the failure count the
/// next pass starts from, or `None` when the loop is over.
fn rotation_pass(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    scope: &RotationScope<'_>,
    last_epoch: &mut mcp_re_http_profile::custody::TrustEpoch,
    consecutive_failures: u32,
) -> Option<u32> {
    if scope.stopped() {
        return None;
    }
    // Skipped while retrying after a failure: the backoff is the wait then, and waiting
    // for the window as well would delay a recovery the window has passed.
    if consecutive_failures == 0 && wait_for_window(scope, last_epoch) {
        return None;
    }
    if scope.stopped() {
        return None;
    }
    rotate_once(rotor, scope, last_epoch)
}

/// The epoch observation and, unless that asks to retry or halt, the rotation attempt.
fn rotate_once(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    scope: &RotationScope<'_>,
    last_epoch: &mut mcp_re_http_profile::custody::TrustEpoch,
) -> Option<u32> {
    match observe_trust_epoch(rotor, scope, last_epoch) {
        EpochStep::Halt => return None,
        EpochStep::Retry(failures) => return Some(failures),
        EpochStep::Proceed => {}
    }
    match attempt_rotation(rotor, scope.signer, scope.overlap, scope.halt) {
        RotationStep::Halt => None,
        RotationStep::Continue(failures) => Some(failures),
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::now_unix;
    use std::time::Duration;

    const NOW: i64 = 1_700_000_100;

    /// A rotor whose snapshot is valid for another hour, so "retired at once" is
    /// distinguishable from "expired on its own".
    fn live_rotor() -> crate::delegated_wiring::ProdDelegatedRotor {
        crate::delegated_wiring::test_support::published(NOW + 3600, 9)
    }

    /// T2. A panic in the rotor retires the snapshot AT ONCE, while its key is still
    /// inside its own window.
    ///
    /// The window is the whole point. A dead rotor with the snapshot left in place keeps
    /// signing until `exp` and then 503s with no attributable cause, and every health
    /// surface reads steady state on the way there: `consecutive_failures` is written only
    /// by this thread, so a dead one leaves it at 0.
    ///
    /// The supervisor is run exactly as production runs it, with only the body replaced.
    /// Before the extraction that was impossible — `SigningPlane::for_teardown_test`
    /// advertises "one that panics" and spawns through `WorkerSet` directly, so it measures
    /// `WorkerSet`, and deleting this supervisor left every test green (R11-572/573/574).
    /// ad1846dc. A rotation worker that stops CLEANLY retires the snapshot too: once nothing
    /// maintains the key — no successor minted, no trust-epoch advance observed — nothing
    /// may sign under it, whoever stopped the worker.
    #[test]
    fn a_rotor_that_stops_cleanly_retires_the_snapshot() {
        let mut rotor = live_rotor();
        let signer = rotor.signer();
        let supervised =
            supervise_delegated_rotation(Arc::clone(&signer), rotor.retirement(), || {});
        std::thread::spawn(supervised)
            .join()
            .expect("the worker ends");
        assert!(
            signer.current(NOW).is_none(),
            "a key nothing maintains must not keep signing until its exp"
        );
        rotor
            .rotate(NOW)
            .expect("a mint after retirement is ignored, not refused");
        assert!(
            signer.current(NOW).is_none(),
            "a straggler mint cannot reopen signing after maintenance stopped"
        );
    }

    #[test]
    fn a_panicking_rotor_retires_the_snapshot_immediately_not_at_exp() {
        let mut rotor = live_rotor();
        let signer = rotor.signer();
        assert!(
            signer.current(NOW).is_some(),
            "a live rotor signs with a key inside its window"
        );
        assert_eq!(signer.metrics().consecutive_failures(), 0);

        // The panic is this test's INPUT, so the hook is quieted for the duration.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let supervised =
            supervise_delegated_rotation(Arc::clone(&signer), rotor.retirement(), || {
                panic!("injected: the rotation body died");
            });
        let joined = std::thread::spawn(supervised).join();
        std::panic::set_hook(hook);

        assert!(
            joined.is_ok(),
            "the supervisor converts the panic; it does not propagate it"
        );
        assert!(
            signer.current(NOW).is_none(),
            "response signing must fail closed NOW, not in an hour when the key expires"
        );
        assert!(
            signer.metrics().consecutive_failures() > 0,
            "the metric only this thread writes must stop reading steady state"
        );

        // Terminal: a straggler mint that lands after the panic cannot restore signing.
        rotor
            .rotate(NOW)
            .expect("a mint after retirement is ignored, not refused");
        assert!(
            signer.current(NOW).is_none(),
            "after a panic the rotor's state is not known good; continuing to mint from it \
             would be worse than refusing"
        );
    }

    struct Unreadable;

    impl crate::trust_epoch::EpochReader for Unreadable {
        fn read_epoch(&self) -> Result<i64, crate::trust_epoch::EpochReadError> {
            Err(crate::trust_epoch::EpochReadError("injected".into()))
        }
        fn read_state(
            &self,
        ) -> Result<crate::trust_epoch::EpochState, crate::trust_epoch::EpochReadError> {
            Err(crate::trust_epoch::EpochReadError("injected".into()))
        }
    }

    impl crate::trust_epoch::raise::EpochRaiser for Unreadable {
        fn raise_past(
            &self,
            _mark: i64,
            _to: i64,
        ) -> Result<i64, crate::trust_epoch::EpochReadError> {
            Err(crate::trust_epoch::EpochReadError("injected".into()))
        }
    }

    /// An unreadable epoch is recorded once, when the wait first sees it, rather than
    /// only when the window opens an hour later; the wait keeps polling until halted.
    #[test]
    fn an_unreadable_epoch_is_recorded_when_first_seen_not_when_the_window_opens() {
        let signer =
            crate::delegated_wiring::test_support::published(now_unix() + 3600, 9).signer();
        let watch =
            DelegatedEpochWatch::new(Box::new(Unreadable), "epoch-1".parse().expect("base"));
        let deployment = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let workers = crate::managed_worker::WorkerSet::new(Arc::clone(&deployment));
        let halt = workers.halt();
        let stopper = std::thread::spawn({
            let deployment = Arc::clone(&deployment);
            move || {
                std::thread::sleep(Duration::from_millis(1200));
                deployment.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let last = "epoch-1"
            .parse::<mcp_re_http_profile::custody::TrustEpoch>()
            .expect("base");
        let scope = RotationScope {
            signer: &signer,
            overlap: 60,
            epoch_watch: Some(&watch),
            halt: &halt,
        };
        let halted = wait_for_window(&scope, &last.at(0));
        stopper.join().expect("stopper thread");

        assert!(
            halted,
            "an unreadable epoch is not an advance; only the halt ends the wait"
        );
        assert_eq!(signer.metrics().consecutive_failures(), 1);
        assert_eq!(signer.metrics().rotation_failures(), 1);
    }

    /// ed248f11: a permanently retired signer ends the loop on its own, with no halt
    /// raised, and records no failure against it. Without the check the loop reads every
    /// pass as "no progress", backs off, and counts on until the halt.
    #[test]
    fn a_permanently_retired_signer_ends_the_loop_without_counting_failures() {
        let mut rotor = crate::delegated_wiring::test_support::published(now_unix() + 3600, 9);
        let signer = rotor.signer();
        rotor.retirement().retire_permanently();
        let deployment = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let workers = crate::managed_worker::WorkerSet::new(Arc::clone(&deployment));
        let halt = workers.halt();
        let (ended_tx, ended) = std::sync::mpsc::channel();
        let worker = std::thread::spawn({
            let signer = Arc::clone(&signer);
            move || {
                let scope = RotationScope {
                    signer: &signer,
                    overlap: 60,
                    epoch_watch: None,
                    halt: &halt,
                };
                rotation_loop(&mut rotor, &scope);
                let _ = ended_tx.send(());
            }
        });
        let ended_alone = ended.recv_timeout(Duration::from_secs(5)).is_ok();
        deployment.store(true, std::sync::atomic::Ordering::SeqCst);
        worker.join().expect("rotation loop thread");

        assert!(
            ended_alone,
            "a retired signer must end the loop without a halt"
        );
        assert_eq!(signer.metrics().rotation_failures(), 0);
    }
}
