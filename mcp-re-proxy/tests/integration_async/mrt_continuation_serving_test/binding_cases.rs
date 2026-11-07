// SPDX-License-Identifier: Apache-2.0
//! The continuation binding: open on one replica, answer on another, and every way a binding or an actor mismatch fails closed.

use super::*;

#[tokio::test]
async fn continuation_opened_on_a_is_honoured_on_b() {
    const STATE: &str = "state-token-A1";

    // Two replicas, distinct signers + replay tiers, ONE shared continuation store.
    let (a, b) = two_replicas(STATE);

    // OPEN on A — A records the retained bases in the shared store.
    let leg = open_on(&a, STATE).await;

    // ANSWER on B — B never saw the open leg. Build the continuation from the handles
    // the client holds (exactly `HttpContinuation::from_handles`).
    let answer_req = leg.answer();
    verify_request(&answer_req);

    let served = serve(&b, &answer_req).await;
    assert_status(&served, 200, "continuation opened on A is honoured on B");
    let resp = http_response(served);
    // The terminal reply is a delegated-signed success bound to the answer request.
    verified_reply_handle(&resp, &answer_req);
    assert!(String::from_utf8_lossy(&resp.body).contains("\"confirmed\":true"));

    // One-shot: a second answer for the same requestState finds no store entry (the
    // first answer's `consume` removed it once it was ADMITTED), so it fails closed
    // regardless of the handles.
    let replay_req = OpenLeg::unopened(STATE).answer();
    let served2 = serve(&b, &replay_req).await;
    assert_refused(
        &served2,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "the continuation is one-shot",
        },
    );
}

#[tokio::test]
async fn answer_without_a_shared_store_entry_fails_closed() {
    const STATE: &str = "state-token-B1";
    // B alone — nothing was ever opened, so the store has no entry for STATE.
    let b = replica(ready_signer(), shared_store(), STATE);

    let served = serve(&b, &OpenLeg::unopened(STATE).answer()).await;
    assert_refused(
        &served,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "no retained bases → fail closed",
        },
    );
}

#[tokio::test]
async fn an_answer_that_fails_the_binding_leaves_the_continuation_answerable() {
    // Reading the retained bases is not a side effect, so a request that is about to be
    // refused cannot take a live continuation down with it. This is what makes the
    // failure recoverable: an approval round trip cannot be re-opened, so destroying it
    // on a rejected request would be permanent.
    const STATE: &str = "state-token-D1";
    let (a, b) = two_replicas(STATE);

    let leg = open_on(&a, STATE).await;

    // A well-formed answer for the RIGHT state whose continuation digests are wrong —
    // the same shape a client hits after losing track of which response it is answering.
    let bad_req = leg.answer_with(leg.mismatched_continuation());
    let served_bad = serve(&b, &bad_req).await;
    assert_refused(
        &served_bad,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "a mismatched continuation is refused",
        },
    );

    // The genuine answer still binds: the refusal cost the client one request, not its
    // continuation.
    let served_good = serve(&b, &leg.answer()).await;
    assert_status(
        &served_good,
        200,
        "the refused answer must not have consumed the continuation",
    );
}

#[tokio::test]
async fn a_second_actor_cannot_touch_the_first_actors_continuation() {
    // `requestState` is minted by the inner application and MCP-RE treats it as opaque
    // — nothing in the profile makes it unguessable. So a peer that verifies must not be
    // able to reach another actor's continuation merely by naming its state, whether or
    // not its own request then succeeds.
    const STATE: &str = "state-token-E1";
    let (a, b) = two_replicas(STATE);

    let leg = open_on(&a, STATE).await;

    // A DIFFERENT verified actor names the first actor's requestState. It holds valid
    // trust-file credentials; it simply is not the actor that opened the leg.
    let served_intruder = serve(&b, &leg.answer_as(&second_actor())).await;
    assert_refused(
        &served_intruder,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "another actor's answer is refused",
        },
    );

    // And the first actor's open leg is untouched.
    let served_good = serve(&b, &leg.answer()).await;
    assert_status(
        &served_good,
        200,
        "the intruder must not have destroyed the victim's continuation",
    );
}

#[tokio::test]
async fn tampered_request_state_breaks_the_binding() {
    const STATE: &str = "state-token-C1";
    let (a, b) = two_replicas(STATE);

    let leg = open_on(&a, STATE).await;
    // The client builds the continuation over the GENUINE state, but the wire request
    // carries a DIFFERENT requestState in params — the proxy keys the store on the wire
    // state (no entry) so the binding cannot be recovered.
    let served = serve(&b, &leg.answer_carrying("state-token-TAMPERED")).await;
    assert_refused(
        &served,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "tampered requestState → fail closed",
        },
    );
}

// ===================== STAGE CONTRACT MATRIX (ADR-MCPRE-058 §9.2) =====================
//
// One test per stage obligation that the end-to-end suite would not catch, each written
// against a NAMED broken implementation. The broken version is stated in the doc comment
// before the test exists, so the test is built to detect a specific defect rather than to
// describe whatever the code currently does.
//
// Common obligation, asserted throughout: a refusal carries exactly the retry posture
// implied by the EXCHANGE state at the point of refusal, never one chosen locally by the
// stage. Since the descriptor refactor a stage cannot express a posture at all — it returns
// a `Refusal` and never sees `RequestProgress` — so these tests pin that separation from
// the outside, where a regression would be visible.

/// **replay_admission_stage** — the nonce is burned STRICTLY LAST.
///
/// Broken implementation this must catch: perform the atomic `check_and_insert` BEFORE the
/// continuation binding check, so a request that goes on to be refused has already consumed
/// its replay slot.
///
/// Why it matters: the client's corrected retry reuses its nonce, and the replay key is
/// `(profile_id, signature_label, actor_id, audience_hash, nonce)` — the body is not in it.
/// A prematurely burned nonce therefore turns a recoverable client error into a permanent
/// one, and reports it as `replay_detected`, which is a claim about the caller's honesty.
#[tokio::test]
async fn a_request_refused_on_the_continuation_binding_has_not_burned_its_nonce() {
    const STATE: &str = "state-token-G1";
    // B's inner backend mints a DIFFERENT state from A's, so B's own open leg below
    // establishes a key of its own. With one shared state the retry would be a second
    // open leg on A's still-live key, which the store now answers `Collision` — a
    // correct refusal, but one that would fail this test for a reason having nothing to
    // do with the nonce it is about. The proposition here is the replay slot; the
    // continuation-key uniqueness rule has its own controls.
    const STATE_B: &str = "state-token-G1-b";
    let nonce = unique_test_nonce();
    let store = shared_store();
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), store, STATE_B);

    let leg = open_on(&a, STATE).await;

    // A well-formed answer whose continuation digests are wrong: refused at the binding,
    // which sits BEFORE the atomic admission.
    let (bad, _e) = signed_request(
        &nonce,
        &answer_body(&leg.state),
        Some(leg.mismatched_continuation()),
    );
    let refused = serve(&b, &bad).await;
    assert_refused(
        &refused,
        Refusal {
            status: 409,
            code: BINDING_FAILED,
            why: "refused at the binding",
        },
    );
    // Nothing was executed and nothing was spent — the peek is not a consume.
    assert_retry_posture(&refused.body, None);

    // The load-bearing assertion: the SAME nonce is still admissible. A different body, so
    // only the shared replay key can make these two collide.
    let (retry, _e) = signed_request(&nonce, OPEN_BODY, None);
    let served = serve(&b, &retry).await;
    assert_status(
        &served,
        200,
        "the refused request must not have consumed the replay slot",
    );

    // Negative control for the assertion above: the nonce IS one-shot once genuinely
    // admitted, so a real replay of it is still refused. Without this, the test would pass
    // against a proxy with no replay tier at all.
    let (again, _e) = signed_request(&nonce, OPEN_BODY, None);
    let replayed = serve(&b, &again).await;
    assert_refused(
        &replayed,
        Refusal {
            status: 409,
            code: "mcp-re.replay_detected",
            why: "an admitted nonce is one-shot",
        },
    );
}

/// **transport_binding_stage** — a configured Mode-A binding cannot be satisfied by silence.
///
/// Broken implementation this must catch: `identity.map(check).unwrap_or(true)` — treat a
/// missing peer identity as "nothing to check, continue" instead of "the evidence this
/// configured policy requires is absent, so the binding cannot be established".
///
/// This is the fail-open shape already seen elsewhere in this codebase:
///
/// ```text
/// required evidence absent -> absence read as "nothing to check" -> condition satisfied
/// ```
///
/// Asserted on the PROTECTED PROPERTY rather than the status: when transport binding is
/// configured, a request lacking peer identity must not advance past the binding stage at
/// all. So the backend must be untouched AND the replay slot unspent — either of which a
/// later, unrelated 403 would fail to guarantee.
///
/// NON-VACUITY. A control that built its own operand —
/// `TransportIdentity::new(verified.resolved_actor().actor_id(), ..)` — could not fail, which
/// is exactly how the wrong binding coordinate survived (ADR-MCPRE-064 §15).
/// `AuthenticatedChannelPeer` cannot be fabricated: it descends from a mechanism adapter's
/// acceptance over a real handshake.
///
/// The positive side of the relation therefore lives where a handshake is available, in
/// `http_profile_serve::request_peer_binding_stage_tests`, which drives a real mutual-TLS
/// certificate whose URI SAN is the resolved SUBJECT and asserts it binds. What stays
/// here is the property this test is about: the stage sits before replay admission and
/// spends nothing, proved by the same nonce still being admissible below.
#[tokio::test]
async fn a_configured_transport_binding_refuses_a_request_that_presents_no_peer_identity() {
    let calls = counter();
    let proxy = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    )
    .with_exact_match_transport_binding();

    // `served_of` presents no `identity` — the plain-HTTP case.
    let tb1 = unique_test_nonce();
    let (req, _e) = signed_request(&tb1, OPEN_BODY, None);
    let served = serve(&proxy, &req).await;

    assert_refused(
        &served,
        Refusal {
            status: 403,
            code: "mcp-re.transport_binding_failed",
            why: "no peer identity cannot satisfy a configured binding",
        },
    );
    assert_eq!(invocations(&calls), 0, "the backend must never be reached");
    // The stage sits BEFORE replay admission, so the slot is untouched: proved by the same
    // nonce still being admissible on a proxy with no binding configured.
    let open = bare_proxy(counting_inner(counter()), ready_signer(), RESPONSE_SIG_TTL);
    let (same_nonce, _e) = signed_request(&tb1, OPEN_BODY, None);
    assert_status(
        &serve(&open, &same_nonce).await,
        200,
        "the refused request must not have advanced far enough to spend anything",
    );
}
