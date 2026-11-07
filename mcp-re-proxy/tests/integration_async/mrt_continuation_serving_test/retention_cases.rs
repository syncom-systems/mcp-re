// SPDX-License-Identifier: Apache-2.0
//! Retention: a reservation or marker failure leaves the backend untouched.

use super::*;

/// **reserve_retention_stage** — the last refusal that is genuinely free.
///
/// Broken implementation this must catch: dispatch to the backend before the durable
/// reservation is acknowledged (or treat the reservation as advisory and continue on
/// error), so a retention outage produces a 503 AFTER the action has already run.
///
/// Why it matters: 503 is a status clients retry, and the retry carries a fresh nonce the
/// replay tier cannot stop. A post-execution 503 therefore runs the action twice.
///
/// Asserted on the BACKEND, not on the status code: the status is identical either way, so
/// only the invocation count distinguishes the correct implementation from the broken one.
#[tokio::test]
async fn a_retention_reservation_failure_leaves_the_backend_untouched() {
    let calls = counter();
    let (dir, retention) = retention_in("untouched");
    let proxy = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_continuation_store(shared_store(), DEFAULT_CONTINUATION_TTL_SECS)
    .with_evidence_retention(retention);
    dir.wedge();

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: RETENTION_UNAVAILABLE,
            why: "the outage is named",
        },
    );
    assert_eq!(
        invocations(&calls),
        0,
        "the backend must not have been reached"
    );
    // No continuation was involved, so the refusal is an ordinary retry.
    assert_retry_posture(&served.body, None);

    // Non-vacuity control: the same proxy with a writable store DOES reach the backend, so
    // the count above is a consequence of the outage and not of a broken harness.
    let (_dir_ok, retention_ok) = retention_in("untouched-ok");
    let calls_ok = counter();
    let healthy = bare_proxy(
        counting_inner(Arc::clone(&calls_ok)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_evidence_retention(retention_ok);
    assert_status(
        &serve_open_call(&healthy).await,
        200,
        "a writable store serves",
    );
    assert_eq!(invocations(&calls_ok), 1);
}

/// **R8-C010 / C048 / C092.** A free refusal never runs after the retention reservation.
///
/// Broken implementation this must catch: order `reserve_retention_stage` BEFORE
/// `inner_plane_stage`. `RetentionReservation` has no `Drop` that unlinks its marker and
/// nothing sweeps `*.pending`, so every request refused at the inner-plane gate — local
/// saturation or an all-ejected backend set, both inducible by an authenticated client
/// with concurrent slow calls — leaves a permanent on-disk record whose documented meaning
/// is "this exact request crossed the execution threshold and its outcome was never
/// retained". The exchange machine reports the same request as `RefusedBeforeDispatch`.
///
/// Asserted on the FILESYSTEM. The status and wire code are identical under both
/// orderings, so only the marker count distinguishes them.
///
/// A plane that refuses to admit anything never transmits: `refusing(..)` is that inner
/// plane here, with every inner backend ejected.
#[tokio::test]
async fn an_inner_plane_refusal_leaves_no_durable_retention_marker() {
    let (dir, retention) = retention_in("no-marker");
    let reader = mcp_re_proxy::transparency::RetainedArchive::open_read_only(dir.path())
        .expect("the retention root is readable");
    let proxy = bare_proxy(
        refusing("every inner backend is ejected"),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_evidence_retention(retention);

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: INNER_PLANE_UNAVAILABLE,
            why: "an all-ejected backend set is unavailable",
        },
    );
    // Nothing ran and nothing was spent, so the refusal is an ordinary retry.
    assert_retry_posture(&served.body, None);
    assert_eq!(
        reader
            .pending_reservations()
            .expect("the retention root is readable"),
        Vec::<String>::new(),
        "a request that provably never reached a backend must leave no execution-threshold \
         marker behind"
    );

    // Non-vacuity: the retention store IS wired and DOES write for an exchange that
    // crosses the threshold — so the zero above is the ordering, not a dead store.
    let (dir_ok, retention_ok) = retention_in("no-marker-ok");
    let calls = counter();
    let healthy = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_evidence_retention(retention_ok);
    assert_status(
        &serve_open_call(&healthy).await,
        200,
        "a writable store serves",
    );
    assert_eq!(invocations(&calls), 1);
    let retained = std::fs::read_dir(dir_ok.path())
        .expect("readable")
        .filter_map(|e| e.ok())
        .count();
    assert!(
        retained > 0,
        "the control must actually have retained something"
    );
}
