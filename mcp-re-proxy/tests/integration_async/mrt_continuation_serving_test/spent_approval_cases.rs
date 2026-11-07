// SPDX-License-Identifier: Apache-2.0
//! A spent approval and an unrun action: the cross-machine seam.

use super::*;

/// ADR-MCPRE-057 §4 — the state that belongs to neither machine alone.
///
/// The answer leg retires its continuation to enforce one-shot, and only THEN reserves
/// retention. A store outage in that window refuses before the backend runs, so the action
/// truly did not happen — but the human approval authorizing it is already gone. A client
/// told only "503" retries, passes replay admission on a fresh nonce, and is refused as
/// already-answered, having burned the approval for nothing.
///
/// Neither machine can state this on its own: the request machine truthfully says the
/// backend did not run, the continuation machine truthfully says the leg was consumed, and
/// the client needs the pair.
#[tokio::test]
async fn an_approval_spent_on_a_request_that_never_ran_is_not_reported_as_retry_safe() {
    const STATE: &str = "state-token-E1";
    let store = shared_store();
    let a = replica(ready_signer(), Arc::clone(&store), STATE);

    let leg = open_on(&a, STATE).await;

    let (dir, retention) = retention_in("spent");
    let b = replica(ready_signer(), store, STATE).with_evidence_retention(retention);
    // Only now does the volume go away — after the proxy proved it writable at startup.
    dir.wedge();

    let served = serve(&b, &leg.answer()).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: RETENTION_UNAVAILABLE,
            why: "refused before the backend could run",
        },
    );
    assert_approval_spent_and_action_unrun(&served);
}

/// Non-vacuity control for the test above. The SAME refusal, at the SAME point, on an
/// exchange that spent no approval carries none of those fields — so the assertions above
/// are pinning the cross-machine state and not just the wire code.
#[tokio::test]
async fn the_same_retention_outage_without_a_spent_approval_stays_an_ordinary_retry() {
    const STATE: &str = "state-token-E2";
    let (dir, retention) = retention_in("unspent");
    let b = replica(ready_signer(), shared_store(), STATE).with_evidence_retention(retention);
    dir.wedge();

    // A plain request: no continuation, so nothing is at stake but the call itself.
    let served = serve_open_call(&b).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: RETENTION_UNAVAILABLE,
            why: "the outage is named",
        },
    );
    assert_states_no_continuation_or_retry_posture(&served);
}

/// **retire_continuation_stage** — a successful consumption is irreversible.
///
/// Broken implementation this must catch: a refusal raised AFTER the consumption reports the
/// exchange as though the approval were still reusable — the state the pre-descriptor code
/// produced, because each refusal site answered the retry question from its own position and
/// no site could see the continuation machine.
///
/// The backend is asserted untouched as well, because the two facts together are the whole
/// contract: the action did NOT run, and the approval is nonetheless gone. Either one alone
/// is a true statement that misleads.
#[tokio::test]
async fn a_consumption_followed_by_a_refusal_reports_a_spent_approval_and_an_unrun_action() {
    const STATE: &str = "state-token-H3";
    let store = shared_store();
    let opener = replica(ready_signer(), Arc::clone(&store), STATE);
    let leg = open_on(&opener, STATE).await;

    let calls = counter();
    let (dir, retention) = retention_in("spent-unrun");
    let answerer = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_continuation_store(store, DEFAULT_CONTINUATION_TTL_SECS)
    .with_evidence_retention(retention);
    dir.wedge();

    let served = serve(&answerer, &leg.answer()).await;

    // The action did NOT run...
    assert_eq!(invocations(&calls), 0, "refused before the dispatch");
    // ...and the refusal says so, while ALSO saying the approval cannot be reused.
    assert_eq!(served.status, 503);
    assert_retry_posture(&served.body, Some("unsafe_without_new_elicitation"));
    assert_execution(&served, "not_executed", "the action did not run");

    // And the approval really is gone: re-answering fails closed rather than succeeding.
    let refused = serve(&answerer, &OpenLeg::unopened(&leg.state).answer()).await;
    assert_eq!(refused.status, 409);
}
