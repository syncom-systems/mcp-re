//! MCPRE-104 (#308) — proxy replay-tier adapter around the HTTP-profile dispatch seam.
//!
//! The profile crate decides what the replay store it is handed SELF-REPORTS
//! ([`DispatchConfig::admit_replay_tier`] over its durability class). The richer
//! DEPLOYMENT classification, [`ReplayDurabilityTier::meets_strict_production_minimum`]
//! (redis-wait-quorum / linearizable acceptable; redis-async / single-store-fail-closed
//! sub-minimum), is deliberately a `mcp-re-proxy` concern (ADR-MCPS-020) and is NOT
//! imported into the profile crate.
//!
//! [`ReplayAdmission::admit`] layers that tier gate ABOVE the profile seam on
//! the serving path:
//!
//! ```text
//!   ┌ proxy tier gate (this module) ──── operator's DEPLOYMENT declaration ┐
//!   │   fleet-strict ⇒ ReplayDurabilityTier::meets_strict_production_minimum │
//!   │   ┌ profile seam ──────────────────── store's RUNTIME self-declaration │
//!   │   │   fleet-strict ⇒ durability_class() != SingleProcessReference      │
//!   │   │   → replay-key build → continuation binding                        │
//!   │   └──────────────────────────────────────────────────────────────────┘ │
//!   │   awaited atomic admit LAST; its answer read by PreparedDispatch::admit │
//!   └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The two gates are complementary, not redundant: the tier gate is what the
//! operator DECLARES the shared store to be; the profile gate is what the wired store
//! self-reports at runtime. A deployment that declares `redis-wait-quorum` but
//! actually wires an in-memory single-process store is still refused by the lower
//! gate — neither substitutes for the other (defense in depth, #308 AT4).
//!
//! What the store answers is not read here. [`PreparedDispatch::admit`] is the one place
//! a replay-store answer becomes an outcome or a refusal, for this path and the profile
//! crate's own sync dispatcher alike.
//!
//! The crate boundary is preserved: the [`ReplayDurabilityTier`] type stays here in
//! `mcp-re-proxy`; `mcp-re-http-profile` gains no dependency on the proxy.
//!
//! [`PreparedDispatch::admit`]: mcp_re_http_profile::PreparedDispatch::admit

use mcp_re_http_profile::DispatchConfig;
use mcp_re_http_profile::DispatchError;
use mcp_re_http_profile::DispatchOutcome;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::VerifiedMcpRequest;

use crate::async_replay::AsyncReplayTier;
use crate::replay_tier::ReplayDurabilityTier;

/// What the deployment declares about its replay store: the posture every admission
/// through [`ReplayAdmission`] runs under.
///
/// There is no fleet-strict posture without a declared tier. Fleet-strict is the claim
/// that a nonce admitted here is refused on every replica, and the tier is what that claim
/// is ABOUT, so a strict posture over an unclassified store is not a posture this type can
/// state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayPosture {
    /// The tier refuses replays within this process only.
    SingleProcess,
    /// Fleet-strict production posture over a shared store declared at this tier
    /// (ADR-MCPS-020). BOTH the [`ReplayDurabilityTier`] strict-production gate (this
    /// module) AND the dispatcher's core single-process refusal apply.
    FleetStrict(ReplayDurabilityTier),
}

impl ReplayPosture {
    fn fleet_strict(&self) -> bool {
        matches!(self, ReplayPosture::FleetStrict(_))
    }

    /// The deployment tier gate: whether what the operator DECLARED the shared replay
    /// store to be clears [`ReplayDurabilityTier::meets_strict_production_minimum`].
    ///
    /// Pure — no store, no await, no side effect — which is what lets the serving path
    /// refuse before anything has been spent.
    ///
    /// Outside fleet-strict it admits: the declaration is load-bearing only where the
    /// operator asked for the strict posture.
    fn deployment_tier_admits(&self) -> Result<(), ProxyDispatchError> {
        match self {
            ReplayPosture::SingleProcess => Ok(()),
            ReplayPosture::FleetStrict(tier) if tier.meets_strict_production_minimum() => Ok(()),
            ReplayPosture::FleetStrict(tier) => {
                Err(ProxyDispatchError::SubMinimumReplayTier(tier.clone()))
            }
        }
    }
}

/// A fail-closed adapter outcome: the tier-gate refusals this layer adds, plus a
/// delegated dispatcher failure. Every variant maps to a frozen `mcp-re.*` wire
/// token (no parallel namespace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDispatchError {
    /// Fleet-strict, but the declared tier is below the strict-production minimum
    /// (`REDIS_ASYNC` or `SINGLE_STORE_FAIL_CLOSED`). Fail closed on the same frozen
    /// token as an operational replay outage — the declared store cannot be relied
    /// upon here. → `mcp-re.replay_cache_unavailable`.
    SubMinimumReplayTier(ReplayDurabilityTier),
    /// The pure dispatcher refused beneath the tier gate (core single-process gate,
    /// replay detected, replay-cache unavailable, continuation binding, or profile
    /// evidence). Delegates its own `wire_code`.
    Dispatch(DispatchError),
}

mod core_projection;

/// The replay store and the posture declared for it, as one value — THE production serving
/// path's replay admission (ADR-MCPRE-051 §4; `http_profile_serve::answering_commitment`).
///
/// The tier and its posture are never handed over apart: whatever admits a request reads
/// the declaration made about the store that answers it. In production the one producer is
/// `replay_plane::MaterializedReplay`, which checked the store's durability first; a value
/// built here directly is still refused per request by both gates in [`Self::admit`], so
/// the constructor is no way around them.
pub struct ReplayAdmission {
    tier: AsyncReplayTier,
    posture: ReplayPosture,
}

impl ReplayAdmission {
    /// The store `tier`, admitting under the declared `posture`.
    pub fn new(tier: AsyncReplayTier, posture: ReplayPosture) -> Self {
        ReplayAdmission { tier, posture }
    }

    /// Drive a verified full-profile request through the replay-tier gate and then the
    /// AUTHORITATIVE ASYNC replay tier.
    ///
    /// The profile crate's sync `dispatch_request` reaches the store's self-report refusal
    /// inside itself. There is no async `dispatch_request`, so this method carries that
    /// refusal, at step 1b, through the same [`DispatchConfig::admit_replay_tier`].
    ///
    /// Ordering (fail closed): the declared-tier gate and the store's
    /// single-process-reference refusal FIRST (both refuse before any side effect), then the
    /// non-side-effecting key construction + continuation binding, then the awaited atomic
    /// admission LAST. `verified` MUST come from
    /// [`mcp_re_http_profile::verify_request_full`].
    pub async fn admit(
        &self,
        verified: &VerifiedMcpRequest,
        continuation_ctx: Option<RetainedContinuation<'_>>,
        now_unix: i64,
    ) -> Result<DispatchOutcome, ProxyDispatchError> {
        // 1a. Deployment tier gate (proxy).
        self.posture.deployment_tier_admits()?;
        // 1b. The store's own self-report. A strong DECLARATION does not excuse a wired
        //     store that says it cannot prevent a cross-node replay. Its product is the
        //     profile crate's key to steps 2–3: without this decision there is nothing to
        //     prepare a dispatch with, so the refusal is a precondition and not a habit.
        let posture = DispatchConfig {
            fleet_strict: self.posture.fleet_strict(),
        };
        let admitted = posture
            .admit_replay_tier(self.tier.durability_class())
            .map_err(ProxyDispatchError::Dispatch)?;

        // 2–3. Native key construction + continuation binding (shared, non-side-effecting).
        //      The borrowed `continuation_ctx` is consumed here, BEFORE the await. The
        //      product is the profile crate's sealed `PreparedDispatch`: this path cannot
        //      assemble an outcome of its own, the proved `continuation_verified` having no
        //      construction site outside the seam that proves it.
        let prepared = admitted
            .prepare(verified, continuation_ctx)
            .map_err(ProxyDispatchError::Dispatch)?;

        // 4. Awaited atomic admission LAST — the only side-effecting step. Its answer is
        //    read by the preparation it was asked about, never here.
        let answer = self
            .tier
            .check_and_insert(&prepared.to_replay_key(verified.expires()), now_unix)
            .await;
        prepared.admit(answer).map_err(ProxyDispatchError::Dispatch)
    }
}

#[cfg(test)]
mod tests {
    // This module is the file's test region: `scripts/module_size_gate.py` opens it at the
    // `#[cfg(test)]` above and stops counting production lines here.
    use super::*;
    use mcp_re_core::ReplayDecision;
    use mcp_re_core::ReplayDurabilityClass;

    use crate::async_replay::AsyncAtomicReplayStore;
    use crate::async_replay::ReplayDecisionFuture;
    use crate::async_replay::ReplayInsert;
    use crate::config_state::FreshnessWindow;
    use crate::shared_replay::ReplayStoreError;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    fn verified() -> VerifiedMcpRequest {
        crate::authorization::action_harness::verified_over_as(
            crate::authorization::action_harness::LIST,
            "did:example:agent-1",
            "key-a",
        )
        .verified
    }

    /// An async store that records whether the tier ever reached it.
    ///
    /// The two gates above the admission step claim to refuse BEFORE any side effect, and
    /// a stub that only returned a decision could not tell that from a refusal taken after
    /// the insert.
    struct WitnessStore {
        touched: Arc<AtomicBool>,
        class: ReplayDurabilityClass,
        /// When set, the store CANNOT establish the state: the insert fails the way an
        /// unreachable or non-acknowledging backend fails, after being reached.
        unavailable: bool,
    }

    impl AsyncAtomicReplayStore for WitnessStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            _insert: ReplayInsert<'a>,
        ) -> ReplayDecisionFuture<'a> {
            self.touched.store(true, Ordering::SeqCst);
            let unavailable = self.unavailable;
            Box::pin(async move {
                if unavailable {
                    return Err(ReplayStoreError::Unavailable {
                        details: "the acknowledgement never arrived".into(),
                    });
                }
                Ok(ReplayDecision::Fresh)
            })
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            self.class
        }
    }

    /// An async tier over a witness store self-reporting `class`, and the flag that store
    /// sets when the admission step reaches it.
    fn async_tier(class: ReplayDurabilityClass) -> (AsyncReplayTier, Arc<AtomicBool>) {
        async_tier_inner(class, false)
    }

    /// The same tier over a store that is reached and then does not answer.
    fn async_tier_unreachable() -> (AsyncReplayTier, Arc<AtomicBool>) {
        async_tier_inner(ReplayDurabilityClass::Durable, true)
    }

    fn async_tier_inner(
        class: ReplayDurabilityClass,
        unavailable: bool,
    ) -> (AsyncReplayTier, Arc<AtomicBool>) {
        let touched = Arc::new(AtomicBool::new(false));
        let store = WitnessStore {
            touched: Arc::clone(&touched),
            class,
            unavailable,
        };
        let freshness = FreshnessWindow::new(5).expect("5s is inside the §5.1 skew bound");
        (AsyncReplayTier::new(Arc::new(store), freshness), touched)
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().expect("rt").block_on(f)
    }

    /// Admit `verified()` through `tier` under `posture`, as the serving path does.
    fn admit(
        tier: AsyncReplayTier,
        posture: ReplayPosture,
    ) -> Result<DispatchOutcome, ProxyDispatchError> {
        block(ReplayAdmission::new(tier, posture).admit(&verified(), None, 1))
    }

    /// THE SERVING PATH: a declared tier below the strict-production minimum is refused
    /// without the async store being touched, and the refusal names what was declared.
    #[test]
    fn the_serving_path_refuses_a_sub_minimum_tier_before_the_store_is_touched() {
        for declared in [
            ReplayDurabilityTier::AsyncReplicatedBounded,
            ReplayDurabilityTier::SingleStoreFailClosed,
        ] {
            let (tier, touched) = async_tier(ReplayDurabilityClass::Durable);
            let err = admit(tier, ReplayPosture::FleetStrict(declared.clone()))
                .expect_err("a sub-minimum tier must refuse under fleet-strict");

            assert_eq!(err, ProxyDispatchError::SubMinimumReplayTier(declared));
            assert!(
                !touched.load(Ordering::SeqCst),
                "the store was consulted before refusal"
            );
        }
    }

    /// THE SERVING PATH, step 1b: the strongest possible DECLARATION does not excuse a
    /// wired async store that self-reports the single-process reference class.
    ///
    /// This is the refusal the async path carries itself, because there is no async
    /// `dispatch_request` beneath it to inherit one from. It is also the case a
    /// declaration-only check would admit: the operator's declaration is strong and the
    /// object actually holding the nonces cannot prevent a cross-node replay.
    #[test]
    fn a_strong_declared_tier_does_not_excuse_a_single_process_async_store() {
        let (tier, touched) = async_tier(ReplayDurabilityClass::SingleProcessReference);
        let err = admit(
            tier,
            ReplayPosture::FleetStrict(ReplayDurabilityTier::Linearizable),
        )
        .expect_err("a single-process async store must be refused under fleet-strict");

        assert_eq!(
            err,
            ProxyDispatchError::Dispatch(DispatchError::NonSharedReplayTier)
        );
        assert!(
            !touched.load(Ordering::SeqCst),
            "the store was consulted before refusal"
        );
    }

    /// Neither serving-path gate fires outside fleet-strict — the negative control for the
    /// two above.
    ///
    /// Without it they are equally satisfied by a gate that refuses every request, which
    /// would establish nothing about the ones that ARE admitted. The store here
    /// self-reports the class step 1b refuses, so this also pins that 1b is conditioned on
    /// the posture and not on the class alone.
    #[test]
    fn neither_serving_path_gate_fires_outside_fleet_strict() {
        let (tier, touched) = async_tier(ReplayDurabilityClass::SingleProcessReference);
        let outcome = admit(tier, ReplayPosture::SingleProcess);

        assert!(
            !matches!(
                outcome,
                Err(ProxyDispatchError::SubMinimumReplayTier(_))
                    | Err(ProxyDispatchError::Dispatch(
                        DispatchError::NonSharedReplayTier
                    ))
            ),
            "a fleet-strict gate fired without fleet-strict"
        );
        assert!(
            touched.load(Ordering::SeqCst),
            "the admission step was not reached"
        );
    }

    /// THE SERVING PATH: a tier meeting the strict minimum over a store that self-reports
    /// a durable class passes both gates and reaches the awaited admission.
    ///
    /// The mirror of the first two under the strict posture: they refuse, this admits,
    /// and the pair is what distinguishes a gate from a blanket refusal.
    #[test]
    fn the_serving_path_admits_a_strict_minimum_tier_over_a_durable_store() {
        let (tier, touched) = async_tier(ReplayDurabilityClass::Durable);
        let outcome = admit(
            tier,
            ReplayPosture::FleetStrict(ReplayDurabilityTier::Linearizable),
        );

        assert!(
            outcome.is_ok(),
            "a strict-minimum tier over a durable store was refused: {outcome:?}"
        );
        assert!(
            touched.load(Ordering::SeqCst),
            "the admission step was not reached"
        );
    }

    /// THE SERVING PATH: an async tier that cannot establish the state the request
    /// requires refuses rather than dispatching, and the verdict is an outage.
    ///
    /// The refusals above are about a POSTURE that is wrong before anything is spent.
    /// This is the other half, and it is the one that decides the proposition on the path
    /// `answering_commitment` runs: the posture is fine, the store is the selected one,
    /// and the acknowledgement does not arrive. The awaited admission is the last step
    /// precisely because there is nothing after it to undo, so its failure must be a
    /// refusal and never a fall-through — and it must not read as a replay, because
    /// "already served" and "nothing was established" are opposite advice to a caller.
    #[test]
    fn the_serving_path_refuses_a_store_that_cannot_establish_the_state() {
        let (tier, touched) = async_tier_unreachable();
        let err = admit(
            tier,
            ReplayPosture::FleetStrict(ReplayDurabilityTier::Linearizable),
        )
        .expect_err("an unestablished replay state must not dispatch");

        assert!(
            touched.load(Ordering::SeqCst),
            "this control is only about the admission step, which must have been reached"
        );
        assert_eq!(
            err,
            ProxyDispatchError::Dispatch(DispatchError::ReplayCacheUnavailable),
            "an outage must not be reported as a replay: {err:?}"
        );
    }
}
