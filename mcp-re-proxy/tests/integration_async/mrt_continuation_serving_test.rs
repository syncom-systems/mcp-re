// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPS-047 stateless cross-replica MRTR continuation, end-to-end through the
//! production PEP (`HttpProfileProxy`) — the serving contract Proof 3 of
//! `docs/security/gke-multi-replica-validation.sh` exercises live.
//!
//! Two independent proxy instances (replica A and replica B) each with their OWN
//! delegated signer and OWN replay tier, but SHARING one continuation correlation
//! store (the in-process stand-in for the fleet-shared Redis tier). Proves:
//!   * OPEN on A: an eliciting inner returns an `InputRequiredResult` with a
//!     `requestState`; A delegated-signs it AND records the retained bases in the
//!     shared store.
//!   * ANSWER on B: a client signs the answer leg with an `HttpContinuation` (built
//!     from the two evidence-handle digests it already holds) + the `requestState`;
//!     B — which never saw the open leg — recovers the retained bases from the shared
//!     store, binds the continuation (digest equality under the client's signature),
//!     forwards to its inner, and delegated-signs a terminal reply. Honoured across a
//!     replica switch.
//!   * Fail-closed: a continuation with NO shared-store entry (never opened / expired
//!     / already answered — the store is one-shot), and a TAMPERED `requestState`,
//!     are both rejected `continuation_binding_failed`. A splice never admits.

mod envelopes;
mod harness;
mod inners;
mod legs;
mod replicas;
mod replies;
mod retention;
mod sdk_fixture;
mod stores;

use std::sync::Arc;

use mcp_re_http_profile::HttpRequest;
use mcp_re_proxy::async_inner::DispatchedOutcome;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_test_paths::unique_test_nonce;

use harness::bare_proxy;
use harness::http_response;
use harness::ready_signer;
use harness::ready_signer_and_retirement;
use harness::second_actor;
use harness::served_of;
use harness::signed_request;
use harness::signer_with_credential_ttl;
use harness::verified_reply_handle;
use harness::verify_request;
use harness::NOW;
use harness::OPEN_BODY;
use harness::RESPONSE_SIG_TTL;
use inners::counter;
use inners::counting_inner;
use inners::eliciting_inner;
use inners::invocations;
use inners::malformed_eliciting_inner;
use inners::refusing;
use inners::replying_with;
use inners::reporting;
use inners::signer_retiring;
use inners::twice_eliciting_inner;
use legs::answer_body;
use legs::exchange;
use legs::open_on;
use legs::OpenLeg;
use replicas::notification_proxy;
use replicas::replica;
use replicas::replica_with_inner;
use replicas::replica_without_store;
use replicas::shared_store;
use replicas::two_replicas;
use replies::advertised_expiry;
use replies::assert_approval_spent_and_action_unrun;
use replies::assert_execution;
use replies::assert_not_possibly_executed;
use replies::assert_refused;
use replies::assert_retry_posture;
use replies::assert_signed_with_inline_delegation;
use replies::assert_states_no_continuation_or_retry_posture;
use replies::assert_status;
use replies::request_state_of;
use replies::result_type_of;
use replies::Refusal;
use replies::BINDING_FAILED;
use replies::CACHE_UNAVAILABLE;
use replies::INDETERMINATE;
use replies::INNER_PLANE_UNAVAILABLE;
use replies::POSSIBLY_EXECUTED;
use replies::RETENTION_UNAVAILABLE;
use replies::UPSTREAM_INVALID;
use retention::retention_in;
use sdk_fixture::Recording;
use sdk_fixture::SdkFixture;
use stores::Outage;
use stores::OutageStore;

const NOTIFICATION_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}"#;

/// Serve `request` on `proxy` at the frozen instant.
async fn serve(proxy: &HttpProfileProxy, request: &HttpRequest) -> ServedHttpResponse {
    proxy.handle(served_of(request), NOW).await
}

/// Serve a freshly signed open call (`OPEN_BODY`, a new nonce) on `proxy`.
async fn serve_open_call(proxy: &HttpProfileProxy) -> ServedHttpResponse {
    serve_body(proxy, OPEN_BODY).await
}

/// Serve a freshly signed `notifications/cancelled` on `proxy`.
async fn serve_notification(proxy: &HttpProfileProxy) -> ServedHttpResponse {
    serve_body(proxy, NOTIFICATION_BODY).await
}

async fn serve_body(proxy: &HttpProfileProxy, body: &[u8]) -> ServedHttpResponse {
    let (req, _ev) = signed_request(&unique_test_nonce(), body, None);
    serve(proxy, &req).await
}

// --- the load-bearing proof: open on A, answer on B -------------------------

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

// --- fail closed: a continuation with no shared-store entry -------------------

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

// --- a rejected answer leg must not destroy a live continuation --------------

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

// --- one actor cannot reach another's continuation ---------------------------

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

// --- fail closed: a tampered requestState breaks the binding -----------------

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

// --- a malformed open leg must not be served as terminal (C059/C060) ---------

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

// --- ADR-MCPRE-058 §10: the response-region controls (rulings D1/D2/D3/D5) ----

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

/// **D2 + D5.** An unparseable backend body is refused, on a deployment with NO
/// continuation store.
///
/// The store posture is the entire point of the test. Until ruling D2, the only
/// unconditional inspection of a reply was a `resultType` classifier that returned
/// `None` for a body that was not JSON — "not this check's business" — and every real
/// envelope check lived inside the open-leg recorder, which returns early with no store
/// wired. So MCP-RE signed unparseable bytes, retained them, recorded
/// `mcp-re.response.signed`, and the client's own verifier then rejected a message the
/// enforcement boundary had vouched for.
///
/// Running this WITHOUT a store is what makes the mutation faithful: with one wired, the
/// recorder catches the body and the test would pass while proving nothing about the
/// validator.
#[tokio::test]
async fn an_unparseable_backend_body_is_refused_even_with_no_continuation_store() {
    for garbage in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"jsonrpc\":\"2.0\","[..],
        &b"<html>502 Bad Gateway</html>"[..],
    ] {
        let proxy = replica_without_store(replying_with(garbage));
        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: UPSTREAM_INVALID,
                why: &format!("{garbage:?} was signed as a response"),
            },
        );
        assert_execution(&served, POSSIBLY_EXECUTED, &format!("{garbage:?}"));
    }
}

/// **D5.** The JSON-RPC envelope rules, enforced end to end on the serving path.
///
/// Each body below is well-formed JSON and would have been signed and served before this
/// ruling. None of them is a legal response to the outstanding request, and MCP-RE is the
/// component with the authority to say so — the client can only refuse afterwards, having
/// already been told the boundary vouched for it.
#[tokio::test]
async fn an_illegal_json_rpc_envelope_is_refused_before_it_is_signed() {
    // The outstanding request is `OPEN_BODY`, whose id is 1.
    for (label, body) in [
        (
            "wrong id",
            r#"{"jsonrpc":"2.0","id":99,"result":{"ok":true}}"#,
        ),
        (
            "id type differs",
            r#"{"jsonrpc":"2.0","id":"1","result":{"ok":true}}"#,
        ),
        ("id absent", r#"{"jsonrpc":"2.0","result":{"ok":true}}"#),
        (
            "both members",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1,"message":"x"}}"#,
        ),
        ("neither member", r#"{"jsonrpc":"2.0","id":1}"#),
        ("jsonrpc absent", r#"{"id":1,"result":{"ok":true}}"#),
        (
            "jsonrpc wrong",
            r#"{"jsonrpc":"1.0","id":1,"result":{"ok":true}}"#,
        ),
        (
            "error member malformed",
            r#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#,
        ),
    ] {
        let proxy = replica_without_store(replying_with(body.as_bytes()));
        let served = serve_open_call(&proxy).await;

        assert_refused(
            &served,
            Refusal {
                status: 502,
                code: UPSTREAM_INVALID,
                why: &format!("{label} was accepted"),
            },
        );
    }
}

/// The mirror, so the test above cannot pass by refusing everything: a LEGAL envelope
/// through the same store-less proxy is still served, and a JSON-RPC error is one of them.
///
/// The second case is the one worth stating. A JSON-RPC error is a valid terminal protocol
/// response — not a malformed message and not a transport failure — and collapsing it into
/// either would end the exchange on the wrong fact.
#[tokio::test]
async fn a_legal_envelope_is_still_served_and_a_json_rpc_error_is_one() {
    for (label, body) in [
        (
            "ordinary result",
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ok":true}}"#,
        ),
        (
            "json-rpc error",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"the tool refused"}}"#,
        ),
        (
            "result with no resultType (pre-2026-07-28 server)",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        ),
    ] {
        let proxy = replica_without_store(replying_with(body.as_bytes()));
        let served = serve_open_call(&proxy).await;

        assert_status(&served, 200, &format!("{label} was refused"));
    }
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

// --- the SDK-boundary fixture for the same defect (C059/C060) ----------------

/// Freeze a delegated-signed exchange whose reply declares itself non-terminal and
/// withholds its `requestState`, so both SDK bindings can prove they REFUSE it.
///
/// A recorded fixture cannot come from the proxy here: a conformant MCP-RE proxy now
/// rejects this body rather than serving it (see the test above), which is the whole
/// point. The malformed reply is therefore signed directly with the same delegated
/// custody the proxy uses — it stands for a non-conformant or hostile server, which
/// is the only place such a reply can now originate.
///
/// Regenerate: `MCP_RE_WRITE_SDK_FIXTURE=1 bazel run //mcp-re-proxy:integration_async_test --
/// mrt_continuation_serving_test::write_malformed_elicitation_sdk_fixture --exact`. Runfiles are symlinks to the
/// source, so the recording under `sdk/fixtures` is rewritten in place.
#[test]
fn write_malformed_elicitation_sdk_fixture() {
    SdkFixture {
        recording: Recording::MalformedElicitation,
        nonce: "nonce-sdk-malformed",
        reply_body: br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#,
        comment: "A delegated-signed reply that declares itself non-terminal and withholds \
                  its requestState. Genuine evidence with a malformed body: both SDK \
                  bindings must REFUSE it, never report it as a terminal result. \
                  Writer: write_malformed_elicitation_sdk_fixture \
                  (mrt_continuation_serving_test) with MCP_RE_WRITE_SDK_FIXTURE=1",
    }
    .write_or_gate();
}

/// Freeze a delegated-signed reply whose `resultType` is outside the set MCP
/// 2026-07-28 defines (MCPRE-495), so both SDK bindings can prove they refuse it
/// rather than reading it as a completed call.
///
/// Defense in depth: a conformant proxy will not sign such a reply at all, so this
/// stands for a non-conformant or hostile server — the only place one can now come
/// from. The evidence is genuine; only the result type is unreadable.
///
/// Regenerate: `MCP_RE_WRITE_SDK_FIXTURE=1 bazel run //mcp-re-proxy:integration_async_test --
/// mrt_continuation_serving_test::write_unrecognized_result_type_sdk_fixture --exact`. Runfiles are symlinks to the
/// source, so the recording under `sdk/fixtures` is rewritten in place.
#[test]
fn write_unrecognized_result_type_sdk_fixture() {
    SdkFixture {
        recording: Recording::UnrecognizedResultType,
        nonce: "nonce-sdk-unrecognized",
        reply_body: br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#,
        comment: "A delegated-signed reply carrying a resultType outside the set MCP \
                  2026-07-28 defines. Genuine evidence this reader cannot classify: both SDK \
                  bindings must REFUSE it, never report it as a terminal result. \
                  Writer: write_unrecognized_result_type_sdk_fixture \
                  (mrt_continuation_serving_test) with MCP_RE_WRITE_SDK_FIXTURE=1",
    }
    .write_or_gate();
}

// --- the cross-machine seam: an approval spent on a request that never ran ---

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

// --- coexistence: a spent approval and a newly opened leg are different facts ---

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

// --- transport binding: absence of evidence is not satisfaction of the check ---

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

// --- answerability: a receipt may not outlive the credential authorizing it ---

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

/// **R8-C047 / C050 / C051 / C081 / C083.** A notification the inner plane did not deliver
/// is not acknowledged with a signed 202.
///
/// Broken implementation this must catch: branch to `answer_notification` before
/// `observe_inner_stage` and drop the `DispatchedOutcome` unread. Every outcome then
/// collapses into one delegated-signed bodyless 202 that the client verifies and, per the
/// SDK contract, treats as the signal to stop — so a `notifications/cancelled` whose answer
/// never came is indistinguishable from one the backend received, under a signature from
/// the enforcement boundary. Because `observe_origin` was never called on that arm, the
/// machine's own guard against serving synthesized transport-failure bytes as a success
/// could not fire either.
///
/// RB-09's split is asserted per outcome. The *nothing was transmitted* half is no longer
/// among them: since #741 it is decided before the exchange commits to a dispatch, by the
/// refusing inner plane, and there is no post-commitment outcome that can claim it.
/// What remains here is the harder case — transmitted with no answer is 504, and the 504
/// states that the message may have been acted on.
#[tokio::test]
async fn a_notification_the_inner_plane_never_delivered_is_not_acknowledged() {
    let timed_out = notification_proxy(DispatchedOutcome::Indeterminate("inner request timed out"));
    let served = serve_notification(&timed_out).await;
    assert_refused(
        &served,
        Refusal {
            status: 504,
            code: INDETERMINATE,
            why: "an undelivered notification is not a 202",
        },
    );
    assert_execution(
        &served,
        POSSIBLY_EXECUTED,
        "a notification transmitted with no answer may have been acted on",
    );
}

/// The other half of the split, and the non-vacuity control for it: a notification the
/// backend RECEIVED is still acknowledged with a bodyless 202.
///
/// Both accepting outcomes are exercised, and `InvalidUpstream` is the load-bearing one.
/// A conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
/// body — no `application/json` content type — which the inner client classifies as an
/// unusable answer from a backend that nevertheless received the message. Refusing it
/// would break every conformant notification, so the split is on delivery, not on
/// whether the reply was usable.
#[tokio::test]
async fn a_delivered_notification_is_still_acknowledged_with_a_202() {
    let replied = notification_proxy(DispatchedOutcome::Replied(Vec::new()));
    let served = serve_notification(&replied).await;
    assert_status(&served, 202, "the backend received the message");
    assert!(served.body.is_empty(), "the 202 is bodyless");

    let bodyless_202 = notification_proxy(DispatchedOutcome::InvalidUpstream(
        "inner backend did not answer application/json",
    ));
    let served2 = serve_notification(&bodyless_202).await;
    assert_status(
        &served2,
        202,
        "a backend that answered 202-no-body received the notification",
    );
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

/// **R8-C053 / C054.** A body that is not a legal JSON-RPC request never reaches the
/// backend, and never earns a signed acknowledgement.
///
/// Broken implementation this must catch: the one in the tree before the validator was
/// wired — the only member ever read on the request side was `id`, by `outstanding_id`,
/// and its ABSENCE was read as "notification". So an object carrying nothing but an
/// evidence block, or a document that is simultaneously a request and a response, or one
/// whose `jsonrpc` is not `"2.0"`, was forwarded to the inner server and then acknowledged
/// with a delegated-signed 202 asserting the enforcement boundary had accepted an MCP
/// message. A `null` id was folded into the notification arm for the same reason, and the
/// two are answered differently — one with a bound signed reply, the other with a
/// bodyless 202.
///
/// Asserted on the BACKEND COUNT, which is the mechanism: every one of these bodies would
/// have produced a plausible-looking response from the proxy either way, and only the
/// dispatch count distinguishes "refused" from "refused after running it".
#[tokio::test]
async fn a_body_that_is_not_a_json_rpc_request_never_reaches_the_backend() {
    let illegal: &[(&str, &[u8])] = &[
        (
            "no method member",
            br#"{"jsonrpc":"2.0","id":1,"params":{}}"#,
        ),
        ("no jsonrpc member", br#"{"id":1,"method":"tools/call"}"#),
        (
            "wrong jsonrpc version",
            br#"{"jsonrpc":"1.0","id":1,"method":"tools/call"}"#,
        ),
        (
            "also a response",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}"#,
        ),
        (
            "scalar params",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":7}"#,
        ),
        (
            "null id folded into a notification",
            br#"{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}"#,
        ),
        ("bare evidence carrier", br#"{"greeting":"hello"}"#),
    ];

    for (name, body) in illegal {
        envelopes::assert_illegal_body_refused(name, body).await;
    }
}

/// The non-vacuity control for the validator: the two LEGAL request shapes still pass, and
/// still reach their own terminals.
///
/// Without this, a validator that refused every body would satisfy the test above.
#[tokio::test]
async fn the_two_legal_request_shapes_still_reach_their_terminals() {
    let calls = counter();
    let bodied = bare_proxy(
        counting_inner(Arc::clone(&calls)),
        ready_signer(),
        RESPONSE_SIG_TTL,
    );
    assert_eq!(serve_open_call(&bodied).await.status, 200);
    assert_eq!(invocations(&calls), 1);

    let notes = notification_proxy(DispatchedOutcome::Replied(Vec::new()));
    assert_eq!(serve_notification(&notes).await.status, 202);
}
