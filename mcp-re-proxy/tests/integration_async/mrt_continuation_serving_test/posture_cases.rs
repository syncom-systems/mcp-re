// SPDX-License-Identifier: Apache-2.0
//! The retry posture a refusal carries: always the one the exchange state implies.

use super::*;

/// **D1, at the exit that made it urgent.** A continuation-record failure lands after the
/// backend has run, and the status it returns is 503 — the status clients retry.
///
/// The broken implementation this must catch is the one that was in the tree: the same
/// 503, with nothing in the body. A client applying ordinary 503 semantics retries, the
/// retry carries a fresh nonce, replay admission passes it, and the action runs twice.
///
/// Asserted on the BODY. A status-only assertion passes against the old behaviour, which
/// is exactly why the old behaviour survived.
#[tokio::test]
async fn a_continuation_record_failure_after_dispatch_never_reads_as_retry_safe() {
    let store = OutageStore::over(shared_store(), Outage::Create);
    let proxy = replica_with_inner(ready_signer(), store, eliciting_inner("state-token-d1"));

    let served = serve_open_call(&proxy).await;

    assert_eq!(served.status, 503);
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "a 503 after the tool ran must not read as an ordinary outage",
    );
    assert_retry_posture(&served.body, Some("unsafe_without_reconciliation"));
}

/// Non-vacuity control for the two above: a PRE-dispatch refusal on the same proxy still
/// reports that nothing executed.
///
/// Without this, both tests would pass against an implementation that stamped
/// `possibly_executed` on every rejection it ever emitted — which would be a different
/// lie, and a worse one, because it would make the field useless.
#[tokio::test]
async fn a_pre_dispatch_refusal_still_reports_that_nothing_executed() {
    let proxy = replica_without_store(eliciting_inner("state-token-nv"));

    let (req, _ev) = signed_request(&unique_test_nonce(), OPEN_BODY, None);
    // Serve it once so the nonce is spent, then replay it: replay admission refuses BEFORE
    // the dispatch.
    let _ = serve(&proxy, &req).await;
    let replayed = serve(&proxy, &req).await;

    assert_refused(
        &replayed,
        Refusal {
            status: 409,
            code: "mcp-re.replay_detected",
            why: "a replay is refused at admission",
        },
    );
    assert_not_possibly_executed(
        &replayed,
        "a replay refused before the dispatch did not execute anything",
    );
}

/// **§8.5 gap (a).** An outcome that arrives AFTER the threshold is reported at the
/// consequence the exchange has already crossed, not at the one the outcome would justify
/// on its own.
///
/// The fixture reports the weakest post-threshold fact there is — transmitted, with no
/// answer. An earlier fixture reported `NotDispatched` from a committed dispatch, the
/// `admit`/`dispatch` race made deterministic; #741 removed that shape: `prepare` takes the
/// permit rather than reading it, so there is no window to lose, and a committed dispatch
/// has no outcome meaning *nothing was transmitted* to construct. What is still worth
/// pinning is the surviving half of the property — a post-threshold outcome does not walk
/// the exchange's consequence back.
///
/// The tempting broken implementation is the one that looks MORE precise: answer from what
/// the far side of the threshold turned out to be, and let the client retry when the
/// evidence looks benign. That is right about the outcome and wrong about the exchange. The
/// floor was set at the dispatch, and monotone consequence is not negotiable against a more
/// precise late observation — if it were, every post-dispatch refinement would be a chance
/// to walk the claim back.
#[tokio::test]
async fn a_post_threshold_outcome_does_not_walk_the_consequence_back() {
    let proxy = replica_without_store(reporting(DispatchedOutcome::Indeterminate(
        "the answer never came",
    )));

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 504,
            code: INDETERMINATE,
            why: "an indeterminate dispatch is a gateway timeout",
        },
    );
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "the floor was set at the dispatch; a late outcome cannot lower it",
    );
}

/// The other side of gap (a), and the reason the test above is not simply pessimism: the
/// SAME outcome, refused BEFORE the threshold, is genuinely retry-safe.
///
/// Without this pair, `a_late_not_dispatched...` would be satisfied by an implementation
/// that stamped `possibly_executed` on every inner-plane failure — which would make the
/// whole D4 hoist pointless, since the hoist exists precisely to keep this case honest.
///
/// There is no dispatch to guard against: a plane that prepares nothing hands back no
/// capability, and transmitting requires one. The absent `dispatch` is the assertion.
#[tokio::test]
async fn a_saturated_plane_refused_before_the_threshold_is_retry_safe() {
    let proxy = replica_without_store(refusing("inner plane is at its in-flight bound"));

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: INNER_PLANE_UNAVAILABLE,
            why: "a saturated plane is unavailable",
        },
    );
    assert_not_possibly_executed(
        &served,
        "nothing was transmitted and the threshold was never crossed",
    );
}

/// **answerable_stage** — the advertised signature window never outlives the credential.
///
/// ```text
/// expires = min(now + sig_ttl_secs, delegated_credential.exp)
/// ```
///
/// Broken implementation this must catch: drop the `.min(a.exp)` and advertise
/// `now + sig_ttl_secs` unconditionally. The receipt then claims a verification lifetime
/// its own credential cannot support, and a verifier refuses the whole thing as
/// `delegation_credential_expired` — the enforcement boundary emitting self-invalidating
/// evidence.
///
/// **The fixture is deliberately asymmetric**, because the obvious one proves nothing: with
/// a response TTL of 300 and a credential also 300 seconds from expiry, `min(300, 300)` and
/// an unclamped `300` are the same number. The clamp executes and decides nothing. Here the
/// credential expires in 40 seconds while the proxy is configured for 300, so correct and
/// broken implementations differ by 260.
#[tokio::test]
async fn a_signed_reply_never_advertises_validity_past_its_delegated_credential() {
    const CREDENTIAL_TTL: i64 = 40;
    const CONFIGURED_TTL: i64 = 300;

    let proxy = bare_proxy(
        counting_inner(counter()),
        signer_with_credential_ttl(CREDENTIAL_TTL),
        CONFIGURED_TTL,
    );

    let served = serve_open_call(&proxy).await;
    assert_status(&served, 200, "the clamped reply is served");

    assert_eq!(
        advertised_expiry(&served),
        NOW + CREDENTIAL_TTL,
        "the reply must be clamped to the credential, not to the configured response TTL"
    );

    // Non-vacuity control: the fixture can discriminate. The unclamped value the broken
    // implementation would produce is a different number, so this assertion is not
    // satisfied by both branches.
    assert_ne!(NOW + CREDENTIAL_TTL, NOW + CONFIGURED_TTL);

    // And the other direction: when the credential outlives the configured window, the
    // configured window is what governs — the clamp is a minimum, not a substitution.
    let long = bare_proxy(
        counting_inner(counter()),
        signer_with_credential_ttl(CONFIGURED_TTL),
        CREDENTIAL_TTL,
    );
    let served2 = serve_open_call(&long).await;
    assert_status(&served2, 200, "the unclamped reply is served");
    assert_eq!(advertised_expiry(&served2), NOW + CREDENTIAL_TTL);
}

// ===================== ROUND 8: EXECUTION CERTAINTY AT THE SEAMS =====================
//
// Four seams where a fact the exchange knows was being flattened into a fact it does not:
// a store outage into a binding failure, an indeterminate `consume` into "nothing was
// spent", a free refusal into a durable execution-threshold marker, and every inner
// outcome into a signed 202. Each test names the broken implementation it must catch, and
// each asserts the MECHANISM — the wire code, the retry contract, the marker on disk, the
// backend count — rather than the status alone, which every one of these shares with the
// behaviour it replaced.

/// **R8-C113.** A shared-tier outage on the answer leg's `peek` is reported as an outage,
/// not as a forged continuation.
///
/// Broken implementation this must catch: `store.peek(key).await.ok().flatten()` — flatten
/// `Err` into the same `None` as "no live entry", so the dispatcher mints
/// `continuation_binding_failed` (409). That code means a splice or a replayed
/// continuation, so an operator paging on it during a Redis blip investigates a forgery
/// incident, and a genuine splice attempt becomes indistinguishable from store health.
///
/// The two halves are asserted together: the outage says `replay_cache_unavailable`, and
/// the splice on a HEALTHY store still says `continuation_binding_failed`. Either alone
/// would pass against an implementation that had merely renamed the code.
#[tokio::test]
async fn a_continuation_store_outage_on_the_answer_leg_is_named_as_an_outage() {
    const STATE: &str = "state-token-R8-peek";
    let healthy = shared_store();
    let a = replica(ready_signer(), Arc::clone(&healthy), STATE);
    let leg = open_on(&a, STATE).await;

    // Replica B shares the entry but cannot read it.
    let blind = OutageStore::over(Arc::clone(&healthy), Outage::Peek);
    let b = replica(ready_signer(), blind, STATE);

    let served = serve(&b, &leg.answer()).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: CACHE_UNAVAILABLE,
            why: "an unreachable shared tier must not be reported as a forged continuation",
        },
    );
    // The peek has no side effect, so nothing was spent and an ordinary retry is correct.
    assert_retry_posture(&served.body, None);

    // Non-vacuity: on a HEALTHY store the code that means "this continuation does not
    // bind" is still exactly that, so the assertion above discriminates.
    let c = replica(ready_signer(), healthy, STATE);
    let refused = serve(&c, &leg.answer_with(leg.mismatched_continuation())).await;
    assert_refused(
        &refused,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "a splice on a healthy store is a binding failure",
        },
    );
}

/// **R8-C011 / C012 / C049 / C084 / C101.** A `consume` that the store never answered is
/// not reported as "nothing was spent".
///
/// Broken implementation this must catch: `Ok(false) | Err(_) => Err(...)` — one refusal
/// for two different facts, with `ContinuationState::Consumed` recorded only on
/// `Ok(true)`. A Redis `DEL` whose reply was lost may well have executed, so the approval
/// may be destroyed; the exchange nonetheless reported `SafeNothingExecuted`, the client
/// read a plain retryable conflict, and its retry passed replay admission on a fresh nonce
/// and then failed permanently as already-answered.
///
/// Asserted on the BODY's retry contract, not the status: both implementations refuse.
#[tokio::test]
async fn an_indeterminate_continuation_retirement_is_never_reported_as_retry_safe() {
    const STATE: &str = "state-token-R8-consume";
    let shared = shared_store();
    let a = replica(ready_signer(), Arc::clone(&shared), STATE);
    let leg = open_on(&a, STATE).await;

    // The answering replica reads the SAME entry the opener recorded — so the binding
    // succeeds and the exchange really does reach the retirement step — and only the
    // atomic removal fails.
    let calls = counter();
    let store = OutageStore::over(shared, Outage::Consume);
    let b = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_continuation_store(store, DEFAULT_CONTINUATION_TTL_SECS);

    let served = serve(&b, &leg.answer()).await;

    // The action did not run...
    assert_eq!(invocations(&calls), 0, "refused before the dispatch");
    // ...the fault is named as the shared tier's, not the caller's...
    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: CACHE_UNAVAILABLE,
            why: "a store that did not answer is not evidence of a forged continuation",
        },
    );
    // ...and the client is told the approval cannot be reused, which is the whole point:
    // an ordinary retry destroys it for nothing.
    assert_approval_spent_and_action_unrun(&served);
}

/// **R8-C070 / C071.** A post-dispatch refusal is signed and states its execution claim
/// even when the signer is retired after the exchange snapshotted its key.
///
/// Broken implementation this must catch: `signed_rejection` re-asks `self.signer.current`
/// and falls back to `unsigned_error` when it is gone, dropping the request binding, the
/// signature AND the `ExecutionDisposition`. `current` returns `None` for a retired signer,
/// which a drain or a failed rotation can produce between ANSWERABLE and a post-dispatch
/// refusal — so during exactly those windows the 504 whose entire purpose is to say "the
/// backend may have acted" left as a bare unsigned body a client cannot distinguish from an
/// on-path forgery, and which its verifier fails closed on as a transport error, i.e. as
/// did-not-run.
#[tokio::test]
async fn a_post_dispatch_refusal_is_signed_with_the_key_the_exchange_snapshotted() {
    let (signer, retirement) = ready_signer_and_retirement();
    let proxy = bare_proxy(signer_retiring(retirement), signer, RESPONSE_SIG_TTL);

    let served = serve_open_call(&proxy).await;

    assert_eq!(served.status, 504);
    assert_signed_with_inline_delegation(&served);
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "the refusal states its execution claim",
    );
    // The signer really is retired: a NEW exchange on the same proxy cannot be answered at
    // all, which is what makes the assertions above about the snapshot and not about a
    // signer that happened to still be live.
    let served2 = serve_open_call(&proxy).await;
    assert_refused(
        &served2,
        Refusal {
            status: 503,
            code: "mcp-re.delegated_signing_unavailable",
            why: "a retired signer cannot answer a new exchange",
        },
    );
}
