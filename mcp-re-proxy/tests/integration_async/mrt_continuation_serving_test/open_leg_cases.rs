// SPDX-License-Identifier: Apache-2.0
//! The open leg: a reply that opens a continuation is served only when it can be answered.

use super::*;

/// THE regression. The proxy's open-leg recorder used to read "declares itself
/// `input_required`, carries no usable `requestState`" as `None` — indistinguishable
/// from a terminal reply. It therefore signed and returned the non-terminal leg with
/// a 200 while recording NO continuation for it, so no answer leg could ever be
/// honoured on any replica: the client held a signed, verified elicitation that was
/// permanently unanswerable, and its correlation entry was closed as if the call had
/// completed.
///
/// Classification now fails closed, so the malformed body is refused instead of
/// being served as a success.
#[tokio::test]
async fn an_open_leg_that_withholds_its_request_state_is_refused_not_served_as_terminal() {
    for malformed in [
        r#"{"resultType":"input_required"}"#,
        r#"{"resultType":"input_required","requestState":null}"#,
        r#"{"resultType":"input_required","requestState":42}"#,
        r#"{"resultType":"input_required","requestState":{"opaque":"x"}}"#,
    ] {
        let proxy = replica_with_inner(
            ready_signer(),
            shared_store(),
            malformed_eliciting_inner(malformed),
        );

        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: UPSTREAM_INVALID,
                why: &format!("a malformed inner reply is a bad gateway, named: {malformed}"),
            },
        );
        // ADR-MCPRE-058 §10 (ruling D1): the backend has already run by the time the reply
        // is classified, so the refusal says so. A 502 alone is not evidence about whether
        // the action executed, and this exit used to offer nothing else.
        assert_execution(
            &served,
            POSSIBLY_EXECUTED,
            &format!("a post-dispatch refusal states its consequence: {malformed}"),
        );
    }
}

/// The mirror, so the test above cannot pass by refusing everything: a WELL-FORMED
/// open leg through the same replica shape is still served and still recorded.
#[tokio::test]
async fn a_well_formed_open_leg_is_still_served_and_recorded() {
    const STATE: &str = "state-token-wf";
    let proxy = replica_with_inner(ready_signer(), shared_store(), eliciting_inner(STATE));

    let leg = open_on(&proxy, STATE).await;
    assert_eq!(leg.state, STATE);
}

/// A terminal reply is unaffected: it has no continuation to record, and nothing
/// about the stricter classification turns "no state" into an error.
#[tokio::test]
async fn a_terminal_reply_is_not_caught_by_the_stricter_classification() {
    let proxy = replica_with_inner(
        ready_signer(),
        shared_store(),
        malformed_eliciting_inner(r#"{"resultType":"complete","confirmed":true}"#),
    );

    let served = serve_open_call(&proxy).await;
    assert_status(&served, 200, "a terminal reply is served normally");
}

/// MCPRE-495: an inner reply whose `resultType` this PEP does not recognize is
/// refused BEFORE it is signed.
///
/// MCP 2026-07-28 closes the set — unrecognized MUST be considered invalid — and
/// the danger is specific rather than theoretical. Read as terminal, an extension's
/// non-terminal result ends the exchange: the client's correlation entry closes, no
/// answer leg is ever signed, and a continuation reaches the application as a
/// completed call. Signing it first would make it worse, because then the
/// enforcement boundary has vouched for a message whose continuation semantics
/// nobody can read.
///
/// Note `completed`: our own reference backend emitted it until this landed. The
/// spec's terminal value is `complete`, and one letter is the whole difference
/// between a recognized result and an unclassifiable one.
#[tokio::test]
async fn an_unrecognized_result_type_is_refused_before_it_is_signed() {
    for unrecognized in [
        r#"{"resultType":"completed","confirmed":true}"#,
        r#"{"resultType":"com.example/deferred"}"#,
        r#"{"resultType":"inputRequired","requestState":"s"}"#,
        r#"{"resultType":7}"#,
    ] {
        let proxy = replica_with_inner(
            ready_signer(),
            shared_store(),
            malformed_eliciting_inner(unrecognized),
        );

        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: "mcp-re.continuation_type_unsupported",
                why: &format!(
                    "an unclassifiable inner reply is a bad gateway naming the unreadable \
                     continuation model: {unrecognized}"
                ),
            },
        );
    }
}

/// The refusal above must not depend on this deployment running MRTR at all. A
/// replica with no continuation store still cannot classify the reply, and the old
/// open-leg check lived inside the `if let Some(store)` block — so a store-less
/// deployment would have signed the unclassifiable reply and returned it.
#[tokio::test]
async fn an_unrecognized_result_type_is_refused_without_a_continuation_store() {
    let proxy = replica_without_store(malformed_eliciting_inner(
        r#"{"resultType":"com.example/deferred"}"#,
    ));

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 502,
            code: "mcp-re.continuation_type_unsupported",
            why: "no store is not a reason to sign it",
        },
    );
}

/// **D3.** An `input_required` reply on a deployment that cannot record the continuation
/// is refused, not served as a successful open leg.
///
/// The broken implementation this must catch is the one that was in the tree: the open-leg
/// recorder returned `Ok(false)` the moment it found no store, so the elicitation was
/// signed and returned with a 200. The client held a signed, verified instruction to
/// continue an exchange for which nothing had been kept, and found out one leg later, as
/// `continuation_binding_failed` — a code that on the wire reads like an attack signal.
///
/// The mutation is faithful only because the reply here is WELL-FORMED: it carries a
/// perfectly usable `requestState`, so nothing upstream of the recorder has any reason to
/// refuse it. `a_well_formed_open_leg_is_still_served_and_recorded` is the other half —
/// the same body through a proxy that HAS a store is served.
#[tokio::test]
async fn an_open_leg_is_refused_when_the_deployment_cannot_make_it_answerable() {
    let proxy = replica_without_store(eliciting_inner("state-token-unstorable"));

    let served = serve_open_call(&proxy).await;

    assert_refused(
        &served,
        Refusal {
            status: 503,
            code: CACHE_UNAVAILABLE,
            why: "an unanswerable elicitation was served as a success",
        },
    );
    // D1. The backend has already run — the elicitation IS the backend's answer.
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "the elicitation is the backend's answer",
    );
}

/// ADR-MCPRE-057 §4 — the coexistence question, end to end.
///
/// `ContinuationState::Consumed` latches, so that a refusal can never report a spent
/// approval as recoverable by an ordinary retry. The question that latch raises is whether
/// it also discards the fact that a NEW leg now exists.
///
/// It does not, and this proves it operationally rather than by argument: answerability
/// lives in the shared continuation store, and the latch is on a projection whose only
/// production reader is `retry_semantics`. The leg opened BY an answer leg is answered here
/// successfully, on a different replica, after its predecessor was consumed.
#[tokio::test]
async fn a_leg_opened_by_an_answer_leg_is_itself_answerable() {
    const FIRST: &str = "state-token-F1";
    const SECOND: &str = "state-token-F2";
    let store = shared_store();
    let make = || {
        replica_with_inner(
            ready_signer(),
            Arc::clone(&store),
            twice_eliciting_inner(FIRST, SECOND),
        )
    };
    let a = make();
    let b = make();

    // Round 1 — the original call opens leg 1 on A.
    let open = signed_request(&unique_test_nonce(), OPEN_BODY, None);
    let round1 = exchange(&a, open, "leg 1 opened").await;

    // Round 2 — answering leg 1 CONSUMES it, and the reply opens leg 2. Served on B, which
    // never saw round 1.
    let answer1 = signed_request(
        &unique_test_nonce(),
        &answer_body(FIRST),
        Some(round1.continuation(FIRST)),
    );
    let round2 = exchange(&b, answer1, "the answer to leg 1 is served and opens leg 2").await;
    assert_eq!(
        request_state_of(&round2.reply.body).as_deref(),
        Some(SECOND),
        "the answer's own reply carries a NEW requestState"
    );

    // Round 3 — the load-bearing assertion. Leg 2 was recorded by an exchange that had
    // ALREADY consumed leg 1. If the latch had discarded the new leg, this fails closed.
    let (answer2, _ev3) = signed_request(
        &unique_test_nonce(),
        &answer_body(SECOND),
        Some(round2.continuation(SECOND)),
    );
    let served3 = serve(&a, &answer2).await;
    assert_status(
        &served3,
        200,
        "the leg opened BY an answer leg is itself answerable",
    );
    assert_eq!(result_type_of(&served3.body).as_deref(), Some("complete"));

    // Negative control: leg 1 really was consumed, so re-answering it fails closed. Without
    // this, the test above could pass on a store that never consumes anything.
    let (replay_req, _e) = signed_request(
        &unique_test_nonce(),
        &answer_body(FIRST),
        Some(round1.continuation(FIRST)),
    );
    let served_again = serve(&b, &replay_req).await;
    assert_refused(
        &served_again,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "leg 1 is one-shot and was spent",
        },
    );
}
