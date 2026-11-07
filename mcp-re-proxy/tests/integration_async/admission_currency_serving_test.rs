// SPDX-License-Identifier: Apache-2.0
//! §7 admission currency through the production PEP (`HttpProfileProxy`) — MCPRE-493.
//!
//! ADR-MCPRE-053 built the evidence: an authority-signed admission assertion, and the
//! binding that ties a call to it. Both were verified by `check_admission`, which the
//! serving path never called. So a call carrying a fresh, correctly-bound assertion
//! was served even after its workload had been revoked — the assertion is a snapshot,
//! and nothing compared it against authoritative state.
//!
//! These are the properties that make admission actually enforced:
//!
//!   * a superseded generation is refused **before the backend runs** — the whole
//!     point of a currency check is to stop work being done on behalf of a workload
//!     whose admission has moved on, and a check after the tool call has already
//!     happened is a log line, not a control;
//!   * a REVOKED workload is refused even though its assertion is still valid;
//!   * an authority that is healthy but has never heard of the workload is a
//!     definitive negative, NOT an outage — routing it into degraded mode would serve
//!     an unknown caller on its own say-so;
//!   * an unreachable authority fails closed unless the deployment opted into a
//!     BOUNDED degraded window, and fails closed again past P;
//!   * and — the property #493 exists for — a revocation written to a SHARED source
//!     is honoured by a replica that never saw the original call.

mod fixtures;
mod outage;
mod rig;
mod wire;

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_proxy::admission_enforcer::AdmissionEnforcement;
use mcp_re_proxy::admission_enforcer::AdmissionFacet;
use mcp_re_proxy::admission_enforcer::AdmissionRefusalClass;
use mcp_re_proxy::admission_source::InMemoryAdmissionSource;
use mcp_re_test_paths::unique_test_nonce;

use fixtures::admission_claims;
use fixtures::admission_store;
use fixtures::admitted_claims;
use fixtures::admitted_source;
use fixtures::authority_key;
use fixtures::issue_assertion;
use fixtures::revoke;
use fixtures::root_key;
use fixtures::sign_state_record;
use fixtures::state_claims;
use fixtures::ABSENT_ADMISSION_EVIDENCE;
use fixtures::ADMISSION_REFUSED;
use fixtures::NOW;
use fixtures::WORKLOAD;
use outage::OutageSwitch;
use rig::degraded_policy;
use rig::recorded_facets;
use rig::recorded_refusal_classes;
use rig::strict_policy;
use rig::RefusesEverything;
use rig::Rig;
use wire::evidence_call;
use wire::wire_code_of;

/// ADMISSION IS NOT AUTHORIZATION (ADR-MCPRE-065 §3).
///
/// The caller here is admitted on every axis §7 measures: a current generation, a genuine
/// assertion from the real authority, bound to this presenter. That is the strongest
/// admission statement this deployment can make, and it grants no application authority at
/// all. A denying policy still refuses, before the backend runs.
///
/// The inverse — an unadmitted caller reaching a granting policy — cannot happen, because
/// admission is ordered first and refuses on its own.
#[test]
fn an_admitted_workload_is_still_refused_by_a_denying_policy() {
    let rig = Rig::strict(admitted_source(5)).authorizing(Arc::new(RefusesEverything));

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.authorization_scope_denied",
        "the refusal is the POLICY's, not admission's — admission had already passed"
    );
    assert_eq!(
        rig.backend_calls(),
        0,
        "the backend must never have been asked"
    );
}

#[test]
fn a_current_admitted_workload_is_served() {
    let rig = Rig::strict(admitted_source(5));

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    assert_eq!(
        served.status,
        200,
        "{}",
        String::from_utf8_lossy(&served.body)
    );
    assert_eq!(rig.backend_calls(), 1);
}

/// A BORROWED assertion does not admit its holder.
///
/// Every field of the binding is derivable from the assertion itself
/// (`AdmissionBinding::opaque_from`), and the assertion is carried in a request body
/// the caller signs — so without a presenter binding, anyone whose own key the PEP
/// resolves could copy an admitted peer's assertion into its own evidence block and
/// pass §7. The assertion here is genuine, current, and signed by the real authority:
/// the ONLY thing wrong with it is that it was issued to somebody else.
#[test]
fn an_assertion_issued_to_another_actor_does_not_admit_this_caller() {
    let rig = Rig::strict(admitted_source(5));
    let mut claims = admitted_claims(5);
    claims.mcp_re_admitted_actor = "client:example.com:did:example:host-b:client-key-2".into();

    let served = rig.serve_claims(&claims, NOW);
    assert_eq!(
        served.status, 403,
        "an assertion naming another actor must not admit this one"
    );
    assert_eq!(
        rig.backend_calls(),
        0,
        "the tool ran on a borrowed admission"
    );
}

/// THE case #493 exists for. The assertion is fresh, correctly bound, and says
/// admitted — but the authority has moved to generation 6. A snapshot does not confer
/// currency.
#[test]
fn a_superseded_generation_is_refused_before_the_backend_runs() {
    let rig = Rig::strict(admitted_source(6));

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    rig.assert_refused(
        &served,
        0,
        "the tool ran for a workload whose admission had been superseded",
    );
}

/// A gate refusal is recorded as the gate's refusal, never as a gate that was not consulted.
#[test]
fn an_admission_refusal_is_recorded_as_the_gates_refusal() {
    let (rig, sink) = Rig::strict(admitted_source(6)).audited();

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    assert_eq!(served.status, 403);
    assert_eq!(
        recorded_facets(&sink, "mcp-re.request.rejected"),
        vec![AdmissionFacet::Refused],
    );
}

/// One refusal through a fresh replica over `source`, and the classes its record carried.
fn refusal_classes_for(
    source: Arc<InMemoryAdmissionSource>,
    claims: Option<&AdmissionClaims>,
) -> Vec<Option<AdmissionRefusalClass>> {
    let (rig, sink) = Rig::strict(source).audited();
    let served = match claims {
        Some(claims) => rig.serve_claims(claims, NOW),
        None => rig.serve_bare(NOW),
    };
    assert_eq!(served.status, 403);
    recorded_refusal_classes(&sink)
}

/// A forged record and an absent one are the same wire refusal and DIFFERENT facts, and the
/// durable record is the only place the difference survives. Each cause the gate can tell
/// apart names itself in the `admission_refusal` coordinate.
#[test]
fn a_refused_admission_names_which_fact_refused_it_in_the_record() {
    use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal as Bad;
    use AdmissionRefusalClass as Class;

    let claims = admitted_claims(5);

    // Nothing published: the authority has nothing to say about this workload.
    let absent = refusal_classes_for(Arc::new(admission_store()), Some(&claims));
    assert_eq!(absent, vec![Some(Class::NoRecord)]);

    // Something published that the authority did not sign.
    let forged = Arc::new(admission_store());
    forged.publish(WORKLOAD, "not-a-record".to_owned());
    assert_eq!(
        refusal_classes_for(forged, Some(&claims)),
        vec![Some(Class::RecordRefused(Bad::Malformed))]
    );

    // An authentic record at a newer generation: a superseded call, not a missing record.
    assert_eq!(
        refusal_classes_for(admitted_source(6), Some(&claims)),
        vec![Some(Class::NotCurrent)]
    );

    // The deployment requires admission and the call presented none.
    assert_eq!(
        refusal_classes_for(Arc::new(admission_store()), None),
        vec![Some(Class::NoEvidence)]
    );
}

#[test]
fn a_revoked_workload_is_refused_though_its_assertion_is_still_valid() {
    let source = admitted_source(5);
    revoke(&source, 5);
    let rig = Rig::strict(source);

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    rig.assert_refused(&served, 0, "the backend ran for a revoked workload");
}

/// A healthy authority that has never heard of this workload is a definitive
/// negative. If it were treated as an outage, an unknown caller would reach the
/// degraded fork and be served on its own assertion — admitted by being unknown.
#[test]
fn an_unknown_workload_is_refused_not_routed_into_degraded_mode() {
    // Degraded mode ENABLED and wide open: if the unknown workload were mistaken for an
    // outage, this policy would serve it.
    let rig = Rig::new(
        Arc::new(admission_store()),
        degraded_policy(3600),
        AdmissionEnforcement::Required,
    );

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    rig.assert_refused(&served, 0, "the backend ran for an unknown workload");
}

#[test]
fn an_unreachable_authority_fails_closed_by_default() {
    let source = OutageSwitch::admitting(5);
    source.set_unavailable(true);
    let rig = Rig::strict(source);

    let served = rig.serve_claims(&admitted_claims(5), NOW);
    rig.assert_refused(&served, 0, "the backend ran with the authority unreachable");
}

/// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
///
/// Degraded mode is a BOUNDED window a deployment opts into, not a fallback — and the
/// thing P has to bound is how long this replica may serve on last-known state while the
/// authority is unreachable. Applied to the presented assertion's `iat` it bounded the
/// **R11-106.** A degraded serve is READABLE as one: the record says `degraded`, and a
/// live-confirmed serve on the same replica says `live-confirmed`.
///
/// `decide` ended in `.map(|_| ())`, so both produced the same trace and an operator could
/// not find the serves this deployment had made WITHOUT confirmation. The fix is not a new
/// Core success event — ADR-MCPS-035 §3 freezes that allowlist — but an independent typed
/// coordinate, on the terms ADR-MCPRE-066 already gives authorization. See
/// `docs/architecture/admission-facet.md`.
///
/// Both halves are asserted on ONE replica in ONE run, because the defect was precisely that
/// the two were indistinguishable: a control reading only the degraded record would pass
/// against an enforcer that reported `Degraded` for everything.
#[test]
fn a_degraded_serve_and_a_live_confirmed_one_are_different_records() {
    let source = OutageSwitch::admitting(5);
    let (rig, sink) = Rig::new(
        Arc::clone(&source) as _,
        degraded_policy(1),
        AdmissionEnforcement::Required,
    )
    .audited();

    assert_eq!(rig.confirm_live().status, 200);

    source.set_unavailable(true);
    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW + 55);
    assert_eq!(
        rig.serve_claims(&fresh, NOW + 60).status,
        200,
        "inside P, the replica serves on its last-known state",
    );

    assert_eq!(
        recorded_facets(&sink, "mcp-re.request.accepted"),
        vec![AdmissionFacet::LiveConfirmed, AdmissionFacet::Degraded],
        "the two serves are different records; before R11-106 they were the same one"
    );
}

/// wrong thing: the revocation channel IS the store, so during a store outage the
/// issuer never learns of a revocation and keeps minting assertions with a current
/// `iat`, and a caller that simply keeps fetching them was served for the whole outage,
/// however long. Every assertion below is FRESH; only the outage ages.
#[test]
fn an_unreachable_authority_serves_within_p_and_fails_closed_past_it() {
    let source = OutageSwitch::admitting(5);
    // P is ONE SECOND, because the window is elapsed time on the monotonic clock and the
    // control ages the OUTAGE by waiting — which is the only thing that ages it. A 120s
    // bound would need a 120s test. `max_clock_skew` keeps the strict policy's value: it
    // governs the assertion-freshness comparison below and does NOT widen this window.
    let rig = Rig::new(
        Arc::clone(&source) as _,
        degraded_policy(1),
        AdmissionEnforcement::Required,
    );

    // The authority is reachable: this call establishes last-known state to serve on.
    let served = rig.confirm_live();
    assert_eq!(served.status, 200, "a live-confirmed admission serves");

    source.set_unavailable(true);

    // 60s into the outage: inside P, and the assertion is fresh.
    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW + 55);
    let served = rig.serve_claims(&fresh, NOW + 60);
    assert_eq!(served.status, 200, "within P, degraded mode serves");
    assert_eq!(rig.backend_calls(), 2);

    // Past P, with an EQUALLY FRESH assertion. A revocation could have propagated by now
    // and this replica would not know it.
    //
    // TWO clocks are moving and only one of them matters. `now` advances by 100 seconds and
    // the assertion is minted just before it, so everything the CALLER controls says this
    // call is as current as the one before it. What closes the window is the outage having
    // lasted longer than P on the monotonic clock — which nothing the caller can obtain
    // moves, in either direction.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let just_issued = admission_claims(5, AdmissionStatus::Admitted, NOW + 155);
    let served = rig.serve_claims(&just_issued, NOW + 160);
    rig.assert_refused(&served, 2, "no third call reached the inner");
}

/// R7-C093, the other half: a replica that has NEVER reached the authority has no
/// last-known state to serve on, so startup is not a confirmation. Degraded mode extends
/// a window that has to have been opened by a real read.
#[test]
fn a_replica_that_never_reached_the_authority_does_not_enter_degraded_mode() {
    let source = OutageSwitch::admitting(5);
    source.set_unavailable(true);
    let rig = Rig::new(source, degraded_policy(120), AdmissionEnforcement::Required);

    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW - 10);
    let served = rig.serve_claims(&fresh, NOW);

    rig.assert_refused(
        &served,
        0,
        "the backend must not run for a workload whose admission was never confirmed here",
    );
}

#[test]
fn a_call_without_admission_evidence_is_refused_when_required_and_served_when_optional() {
    let strict = Rig::strict(Arc::new(admission_store()));
    let served = strict.serve_bare(NOW);
    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        ABSENT_ADMISSION_EVIDENCE,
        "absent evidence is not an unreachable authority"
    );
    assert_eq!(strict.backend_calls(), 0);

    let lenient = Rig::new(
        Arc::new(admission_store()),
        strict_policy(),
        AdmissionEnforcement::Optional,
    );
    let served = lenient.serve_bare(NOW);
    assert_eq!(served.status, 200);
    assert_eq!(lenient.backend_calls(), 1);
}

/// An assertion signed by a key the deployment does not trust as an admission
/// authority is refused — even though the key is a perfectly good Ed25519 key and the
/// call's own request signature verifies.
#[test]
fn an_assertion_from_an_untrusted_authority_is_refused() {
    let rig = Rig::strict(admitted_source(5));

    // Signed by the RESPONSE-signing root, which is trusted — for responses.
    let served = rig.serve_signed_by(&admitted_claims(5), &root_key(), NOW);
    assert_eq!(served.status, 403);
    assert_eq!(rig.backend_calls(), 0);
}

/// The cross-replica property #493 was opened for, at last testable: a revocation
/// written to the SHARED source is honoured by a replica that never saw the workload's
/// earlier traffic. The replicas share nothing else — separate signers, separate
/// replay tiers — so it is the source that carries the revocation, not shared memory
/// of the call.
#[test]
fn a_revocation_on_the_shared_source_is_honoured_by_a_replica_that_never_saw_the_workload() {
    let source = admitted_source(5);
    let claims = admitted_claims(5);
    let replica_a = Rig::strict(Arc::clone(&source) as _);
    let replica_b = Rig::strict(Arc::clone(&source) as _);

    // A serves the workload happily.
    assert_eq!(replica_a.serve_claims(&claims, NOW).status, 200);

    // The authority revokes it. Nothing tells B; B simply consults the shared source.
    revoke(&source, 5);

    let served = replica_b.serve_claims(&claims, NOW);
    replica_b.assert_refused(&served, 0, "B ran the backend for a revoked workload");

    // And A, which had already served it, refuses the next one too.
    let served = replica_a.serve_claims(&claims, NOW);
    assert_eq!(served.status, 403);
    assert_eq!(
        replica_a.backend_calls(),
        1,
        "only the pre-revocation call ran"
    );
}

/// A generation that is NEWER than the authority's is refused too. The currency rule
/// is equality, not "at least": a call claiming a generation the authority has not
/// issued is not a fresher client, it is a client asserting an admission nobody made.
#[test]
fn a_generation_ahead_of_the_authority_is_refused() {
    let rig = Rig::strict(admitted_source(5));

    let served = rig.serve_claims(&admitted_claims(9), NOW);
    rig.assert_refused(&served, 0, "the backend ran for a generation nobody issued");
}

/// The authoritative record is consulted by ADMISSION ID, and the id comes from the
/// signed binding — so a call cannot borrow another workload's admission by naming it,
/// because the binding it names must also match the assertion it carries.
#[test]
fn a_binding_naming_another_workload_does_not_borrow_its_admission() {
    let source = admitted_source(5);
    // A genuine, currently-admitted record for a DIFFERENT workload, published under its
    // own name. The point of the test is that naming it in a binding does not borrow it.
    let other = state_claims("workload-other", 5, 1, AdmissionStatus::Admitted);
    source.publish(
        "workload-other",
        sign_state_record(&other, &authority_key()),
    );
    let rig = Rig::strict(source);

    // The assertion is for WORKLOAD; the binding claims `workload-other`. The two must
    // describe the same admission, so this is refused as a binding mismatch rather
    // than being looked up against the other workload's healthy record.
    let claims = admitted_claims(5);
    let mut binding = AdmissionBinding::opaque_from(&claims);
    binding.admission_id = "workload-other".into();
    let assertion = issue_assertion(&claims, &authority_key());
    let req = evidence_call(Some(binding), Some(assertion), &unique_test_nonce());

    let served = rig.serve(&req, NOW);
    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.request_binding_mismatch"
    );
    assert_eq!(rig.backend_calls(), 0);
}

// ---------------------------------------------------------------------------------------
// A store writer is not an admission authority — at the serving path (r11 critical R11-505)
// ---------------------------------------------------------------------------------------
//
// The unit batteries in `admission_state_record` and `admission_source` establish what the
// verifier refuses. These establish what the DEPLOYMENT does with those refusals, which is
// the half a verifier cannot state about itself: every one of them is a refusal that must
// not become an outage, because an outage reaches the §5.2 degraded fork and would be
// served on the caller's own assertion. Corrupting a record must never be a cheaper
// un-revoke than issuing one.

/// **Corrupting a record while the store is reachable does not admit anybody.**
///
/// The store answered; it simply has nothing this deployment will act on. That is a
/// definitive negative, and it stays one even with degraded mode enabled and its window
/// open — which is the configuration in which the opposite classification would serve the
/// caller on its own assertion.
#[test]
fn a_corrupt_record_on_a_reachable_store_is_refused_and_never_degraded() {
    let source = admitted_source(5);
    let rig = Rig::with_an_open_degraded_window(&source);

    for (label, corrupt) in [
        ("garbage", "not-a-record".to_owned()),
        ("empty", String::new()),
        ("the old two-field form", "5:admitted".to_owned()),
    ] {
        source.publish(WORKLOAD, corrupt);
        let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW + 5);
        let served = rig.serve_claims(&fresh, NOW + 10);
        assert_eq!(served.status, 403, "{label}: a corrupt record must refuse");
        assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED, "{label}");
    }
    assert_eq!(
        rig.backend_calls(),
        1,
        "only the window-opening call reached the inner"
    );
}

/// **A record signed by anything but the configured authority does not admit anybody.**
///
/// This is the mint. A party that can write the store, and can sign with its own key,
/// still cannot produce an admission — and cannot pick an arbitrarily high generation to
/// outrun the real authority, because it cannot sign one.
#[test]
fn a_record_minted_by_a_store_writer_is_refused_and_never_degraded() {
    let source = admitted_source(5);
    let rig = Rig::with_an_open_degraded_window(&source);

    let attacker = SigningKey::from_seed_bytes(&[77u8; 32]);
    // An arbitrarily high generation, which is exactly what a store-only writer would reach
    // for to outrun the authority's anti-rollback counter.
    let high = state_claims(WORKLOAD, u64::MAX, u64::MAX, AdmissionStatus::Admitted);
    source.publish(WORKLOAD, sign_state_record(&high, &attacker));

    let fresh = admission_claims(u64::MAX, AdmissionStatus::Admitted, NOW + 5);
    let served = rig.serve_claims(&fresh, NOW + 10);
    rig.assert_refused(&served, 1, "only the window-opening call reached the inner");
}

/// **An expired authenticated record on a reachable store does not admit anybody.**
///
/// The signature is genuine and the authority really did publish it. It is simply past the
/// deployment's declared currentness budget, which is the whole anti-rollback mechanism:
/// nothing here detects a substitution, and nothing has to.
#[test]
fn an_expired_authentic_record_on_a_reachable_store_is_refused_and_never_degraded() {
    let source = admitted_source(5);
    let rig = Rig::with_an_open_degraded_window(&source);

    // A record the authority really published, whose window has since closed. The CALL is
    // fresh — the request signature and the assertion are both current — so the only stale
    // thing is the authoritative state, which is the proposition. (Advancing `now` past the
    // record instead would expire the request signature first and refuse for the wrong
    // reason; that is what the first draft of this test measured.)
    let mut stale = state_claims(WORKLOAD, 5, 1, AdmissionStatus::Admitted);
    stale.iat = NOW - 100;
    stale.nbf = NOW - 100;
    stale.exp = NOW - 40;
    source.publish(WORKLOAD, sign_state_record(&stale, &authority_key()));

    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW + 5);
    let served = rig.serve_claims(&fresh, NOW + 10);
    rig.assert_refused(&served, 1, "only the window-opening call reached the inner");
}

/// **The exact attack the r11 ruling pins, end to end on the serving path.**
///
/// ```text
/// t0  the authority admits the workload and the replica serves it
/// t1  the authority revokes; the replica refuses
/// t2  a party with store-write access restores the t0 bytes verbatim
/// ```
///
/// The restored record is genuinely signed and nothing detects that it was restored. It
/// does not restore service, because this replica has already accepted a later publication
/// — and on a replica that has not, the currentness budget closes it anyway (measured in
/// `admission_state_record::currentness` and `redis_admission_source`).
#[test]
fn restoring_a_revoked_workloads_old_admitted_record_does_not_restore_service() {
    let source = Arc::new(admission_store());
    let admitted = sign_state_record(
        &state_claims(WORKLOAD, 5, 1, AdmissionStatus::Admitted),
        &authority_key(),
    );
    source.publish(WORKLOAD, admitted.clone());
    let rig = Rig::strict(Arc::clone(&source) as _);
    let claims = admission_claims(5, AdmissionStatus::Admitted, NOW - 30);

    let served = rig.serve_claims(&claims, NOW);
    assert_eq!(served.status, 200, "t0: the workload is admitted");

    // t1 — revocation, same generation, next publication.
    revoke(&source, 5);
    let served = rig.serve_claims(&claims, NOW + 1);
    assert_eq!(served.status, 403, "t1: the revocation is honoured");

    // t2 — the old bytes restored verbatim. Genuine signature, genuine authority.
    source.publish(WORKLOAD, admitted);
    let served = rig.serve_claims(&claims, NOW + 2);
    assert_eq!(
        served.status, 403,
        "t2: store-write access without the signing authority did not un-revoke"
    );
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(
        rig.backend_calls(),
        1,
        "only the t0 call ever reached the inner"
    );
}
