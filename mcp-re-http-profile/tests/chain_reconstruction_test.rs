// SPDX-License-Identifier: Apache-2.0
//! Retained-chain reconstruction (#416 rev 2 §9, issue #431).
//!
//! The property under test is the one §9.3 exists for: a missing middle hop must
//! yield an INCOMPLETE call record, never a complete-looking terminal result.
//! Every message in these chains verifies on its own — that is what makes the
//! failure worth a test. Per-hop validity is not chain integrity.

#[path = "chain_reconstruction_test/fixtures.rs"]
mod fixtures;
#[path = "chain_reconstruction_test/turns.rs"]
mod turns;
#[path = "chain_reconstruction_test/verify.rs"]
mod verify;

use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_test_paths::unique_test_nonce;

use fixtures::{
    audience, audience_named, block, client_key, resolver, unsigned_request, AWAITING,
    CLIENT_KEY_ID, CREATED, DONE, EXPIRES, NOW, TARGET,
};
use turns::{
    aged_chain, answer_outside_the_full_signer, chain, hop, hop_at, hop_with_bad_window,
    hop_with_block, three_hop_chain,
};
use verify::{
    assert_each_hop_verifies_alone, assert_incomplete, assert_request_unverifiable_at_hop_0,
    outcome, reconstruct, reconstruct_against, reconstruct_at,
};

// --- positives ---------------------------------------------------------------

#[test]
fn multi_hop_chain_reconstructs_complete() {
    let hops = three_hop_chain();
    let label = reconstruct(&hops);
    assert_eq!(
        label,
        ChainLabel::Complete,
        "every hop verifies and re-links"
    );
}

#[test]
fn single_terminal_hop_reconstructs_complete() {
    let h0 = hop(None, DONE);
    assert_eq!(reconstruct(&[h0.retained]), ChainLabel::Complete);
}

#[test]
fn complete_chain_reports_every_hops_evidence() {
    let out = outcome(&three_hop_chain());
    assert!(out.label().is_complete());
    assert_eq!(
        out.hop_evidence().len(),
        3,
        "the record accounts for all 3 hops"
    );
    // Request-role and response-role handles are domain-separated (§7.3), so no
    // hop's two handles collide even though both digest a signature base.
    for h in out.hop_evidence() {
        assert_ne!(
            h.request_evidence.digest_value(),
            h.response_evidence.digest_value()
        );
    }
}

// --- the missing middle hop (§9.1/§9.3) --------------------------------------

/// THE test this module exists for. Drop R1→S1 from a 3-hop chain and hand the
/// auditor R0→S0 and R2→S2. Both remaining hops verify perfectly; S2 is a
/// genuine, correctly-signed terminal result. It must still be labeled
/// INCOMPLETE, naming hop 1 — because R2's continuation links to a turn that is
/// not in the record.
#[test]
fn missing_middle_hop_is_incomplete_not_a_complete_terminal() {
    let all = three_hop_chain();
    let truncated = vec![all[0].clone(), all[2].clone()];

    assert_each_hop_verifies_alone(&truncated);

    let label = reconstruct(&truncated);
    assert_eq!(
        label,
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
        "a terminal answer whose predecessor is absent does not complete the call"
    );
    assert!(!label.is_complete());
}

/// The same record, read naively: every hop is valid, so a checker that only
/// verified signatures would call this complete. Pinning the contrast makes the
/// regression obvious if reconstruction ever softens to a per-hop loop.
#[test]
fn per_hop_validity_does_not_imply_a_complete_chain() {
    let all = three_hop_chain();
    let out = outcome(&[all[0].clone(), all[2].clone()]);
    assert!(!out.label().is_complete());
    // The verified prefix is still reported: hop 0 IS accounted for. An auditor
    // learns which part of the record stands, not merely that it failed.
    assert_eq!(out.hop_evidence().len(), 1);
}

// --- other incomplete shapes -------------------------------------------------

/// A truncated chain: the record stops on a turn still awaiting input. Every hop
/// verifies; the call simply has no ending.
#[test]
fn chain_ending_non_terminally_is_incomplete() {
    let all = three_hop_chain();
    assert_incomplete(&all[..2], 1, IncompleteReason::TerminalExpected);
}

/// THE front-truncation test. Given a real 3-hop call, submit only hops 1 and 2.
/// Every submitted hop verifies, hop 2 re-links to hop 1, and hop 2 is terminal —
/// so every check but one says "complete". The one that must catch it is hop 0's
/// own continuation: it names a predecessor the record cannot produce, so the
/// record starts after the call did.
///
/// Without the hop-0 check this reconstructs as `Complete`, and a SCITT Signed
/// Statement over it reports `is_complete_record() == true` while the opening
/// turns — the original request, its audience and its artifact bindings — are
/// missing. That is the truncated-record laundering §9.3 forbids, from the one
/// direction the shape checks do not cover.
#[test]
fn front_truncated_chain_is_incomplete_not_a_complete_record() {
    let all = three_hop_chain();
    let front_truncated = vec![all[1].clone(), all[2].clone()];

    assert_each_hop_verifies_alone(&front_truncated);

    let out = outcome(&front_truncated);
    assert_eq!(
        out.label(),
        &ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
        "a hop that names a predecessor absent from the record does not open a call"
    );
    assert!(!out.label().is_complete());
    // Nothing is reported as accounted for: the break is at the first hop.
    assert!(out.hop_evidence().is_empty());
}

/// The complementary positive: a genuine opening hop carries NO continuation and
/// still reconstructs. Without this the hop-0 rule could be tightened into
/// rejecting every chain and the negative above would still pass.
#[test]
fn an_opening_hop_without_a_continuation_still_opens_a_complete_record() {
    assert_eq!(reconstruct(&three_hop_chain()), ChainLabel::Complete);
}

/// A hop after the first with no continuation at all: nothing links it backwards.
#[test]
fn later_hop_without_a_continuation_is_incomplete() {
    let h0 = hop(None, AWAITING);
    let h1 = hop(None, DONE);
    assert_incomplete(
        &[h0.retained, h1.retained],
        1,
        IncompleteReason::MissingContinuation,
    );
}

/// A continuation naming a DIFFERENT chain's evidence. The handles are
/// well-formed and the messages verify; they simply do not describe this record.
#[test]
fn continuation_from_another_chain_is_incomplete() {
    let h0 = hop(None, AWAITING);
    let other = hop(None, AWAITING);
    let h1 = hop(Some(other.continuation(b"state-x")), DONE);
    assert_incomplete(
        &[h0.retained, h1.retained],
        1,
        IncompleteReason::ContinuationDoesNotLink,
    );
}

/// A chain that claims to continue past a turn that already answered terminally.
#[test]
fn terminal_before_the_end_is_incomplete() {
    let h0 = hop(None, DONE);
    let h1 = hop(Some(h0.continuation(b"state")), DONE);
    assert_incomplete(
        &[h0.retained, h1.retained],
        0,
        IncompleteReason::NonTerminalExpected,
    );
}

/// Role substitution (§7.3): a continuation that names the previous REQUEST's
/// handle in the response slot. Domain separation means the lifted handle is a
/// different value in that role, so re-linking rejects it.
#[test]
fn handles_swapped_between_roles_do_not_relink() {
    let h0 = hop(None, AWAITING);
    let h1 = hop(Some(h0.role_swapped_continuation(b"state")), DONE);
    assert_incomplete(
        &[h0.retained, h1.retained],
        1,
        IncompleteReason::ContinuationDoesNotLink,
    );
}

/// An unverifiable hop names itself, so an auditor knows which turn to distrust.
#[test]
fn tampered_hop_is_named_by_index() {
    let mut hops = three_hop_chain();
    hops[1].response.body = DONE.as_bytes().to_vec(); // breaks its content-digest
    let out = reconstruct(&hops);
    match out {
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ResponseUnverifiable(_),
        } => {}
        other => panic!("expected hop 1 named unverifiable, got {other:?}"),
    }
}

#[test]
fn empty_chain_is_incomplete() {
    assert_incomplete(&[], 0, IncompleteReason::EmptyChain);
}

/// THE regression for the detached-classification hole. A chain whose last hop is
/// a signed `InputRequiredResult` is TRUNCATED: the call has no ending. Previously
/// a caller could pass `HopOutcome::Terminal` alongside it and the chain would
/// reconstruct as COMPLETE — the classification was authoritative over the
/// protected bytes that contradicted it.
///
/// The classification is now read from the response body that just verified, so
/// there is no parameter left to lie with. The truncated chain is incomplete
/// because its own protected content says the turn was still awaiting input.
#[test]
fn a_truncated_chain_cannot_be_relabelled_complete() {
    let all = three_hop_chain();

    // Both hops verify, and hop 1's response is a genuine, correctly-signed
    // InputRequiredResult — the record simply stops mid-call.
    assert_eq!(
        reconstruct(&all[..2]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::TerminalExpected,
        },
        "protected content says the last turn awaited input; nothing can override it"
    );
}

/// The mirror: terminality is read from the bytes, so a genuinely terminal ending
/// is recognised without anyone asserting it.
#[test]
fn terminality_is_derived_from_protected_content() {
    assert_eq!(reconstruct(&three_hop_chain()), ChainLabel::Complete);

    // Flip ONLY the last response's protected classification (re-signed), and the
    // same hops become a truncated chain — the label tracks the bytes.
    let still_awaiting = chain(&[
        (CREATED, EXPIRES, AWAITING),
        (CREATED, EXPIRES, AWAITING), // the final turn still awaits input
    ]);
    assert_incomplete(&still_awaiting, 1, IncompleteReason::TerminalExpected);
}

/// MCPRE-495: a hop whose `resultType` this reader does not recognize makes the
/// record incomplete AT THAT HOP, rather than being read as terminal.
///
/// This is the direction that matters. Reconstruction is the one reader for which
/// "unknown ⇒ terminal" looks safe — a false truncation is only a false alarm —
/// but it is not safe at the END of a chain: if the last hop carries an extension's
/// non-terminal result, unknown-as-terminal reports a chain that stops mid-call as
/// COMPLETE. An auditor is owed "hop 1 declares a result type I cannot classify",
/// not a confident verdict derived from a value nobody read.
#[test]
fn an_unrecognized_result_type_makes_the_record_incomplete_at_that_hop() {
    const UNRECOGNIZED: &str =
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#;

    let hops = chain(&[
        (CREATED, EXPIRES, AWAITING),
        (CREATED, EXPIRES, UNRECOGNIZED),
    ]);

    assert_eq!(
        reconstruct(&hops),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::UnrecognizedResultType,
        },
        "every message verifies and re-links; whether the call ENDED is what is unknown"
    );
}

/// The same value at a NON-final hop is refused too. Here unknown-as-terminal would
/// have produced `NonTerminalExpected` — an accurate-sounding label for the wrong
/// reason, blaming the chain's shape for what is really an unreadable result type.
#[test]
fn an_unrecognized_result_type_mid_chain_is_named_for_what_it_is() {
    const UNRECOGNIZED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"partial"}}"#;

    let hops = chain(&[(CREATED, EXPIRES, UNRECOGNIZED), (CREATED, EXPIRES, DONE)]);

    assert_incomplete(&hops, 0, IncompleteReason::UnrecognizedResultType);
}

// --- the record is verified as a record, not as live traffic (C033) ----------

/// The audit instant: a year after the last hop closed. Every window in the
/// chain is long shut.
const AUDIT_LATER: i64 = CREATED + 31_536_000;

#[test]
fn an_aged_multi_hop_record_still_reconstructs_complete() {
    let out = reconstruct_at(&aged_chain(), AUDIT_LATER);
    assert_eq!(
        out.label(),
        &ChainLabel::Complete,
        "an intact record does not stop being intact because it got old"
    );
    assert_eq!(out.hop_evidence().len(), 3);
}

/// The precondition that makes the test above meaningful: these hops genuinely
/// are outside each other's windows and outside the audit instant's. If a future
/// refactor narrowed the gaps, the test would still pass while proving nothing.
#[test]
fn the_aged_chains_hops_really_are_out_of_window_at_audit_time() {
    for (i, h) in aged_chain().iter().enumerate() {
        let err = Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_request_floor(&h.request, AUDIT_LATER)
            .expect_err("hop {i}'s window is closed at the audit instant");
        assert!(
            matches!(err, HttpProfileError::StaleWindow),
            "hop {i} should be stale against the live clock, got {err:?}"
        );
    }
}

/// Aging must not be the only thing that changed. A record is still refused if a
/// hop is dated AFTER the audit instant — `now` did not stop mattering, it became
/// a ceiling rather than a window.
#[test]
fn a_hop_created_after_the_audit_instant_is_refused() {
    // Audit as of a moment between hop 0 and hop 1: hop 1 has not happened yet.
    let audit_at = CREATED + 3_600;
    assert_eq!(
        reconstruct_at(&aged_chain(), audit_at).label(),
        &ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::HopAfterAuditInstant,
        },
        "a record cannot contain evidence from after the audit"
    );
}

/// The ceiling allows the same skew the live path does, so an archivist whose
/// clock trails the signer's does not reject its own honest records.
#[test]
fn the_audit_ceiling_tolerates_the_configured_skew() {
    let policy = VerifierPolicy::default();
    let h0 = hop_at(CREATED, CREATED + 300, None, DONE).retained;
    let hops = std::slice::from_ref(&h0);

    let within = CREATED - policy.max_clock_skew();
    assert_eq!(
        reconstruct_at(hops, within).label(),
        &ChainLabel::Complete,
        "a hop one skew ahead of the auditor's clock is honest disagreement"
    );

    let beyond = CREATED - policy.max_clock_skew() - 1;
    assert_eq!(
        reconstruct_at(hops, beyond).label(),
        &ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::HopAfterAuditInstant,
        },
        "one second past the tolerance is no longer disagreement"
    );
}

/// Verifying each hop at its own `created` must not have relaxed the checks that
/// are properties of the MESSAGE rather than of the clock. An over-wide window is
/// still refused, at any age — otherwise "verify it at its own created" would be
/// a way to smuggle a decade-long signature into a retained record.
#[test]
fn an_over_wide_window_is_still_refused_in_an_aged_record() {
    let policy = VerifierPolicy::default();
    let h0 = hop_with_bad_window(CREATED, CREATED + policy.max_signature_validity() + 1);
    assert_request_unverifiable_at_hop_0(
        &reconstruct_at(&[h0], AUDIT_LATER),
        HttpProfileError::StaleWindow,
    );
}

/// And the degenerate window: `expires <= created` leaves no instant at all, so
/// there is nothing for "its own created" to fall inside. It must not become
/// self-satisfying.
#[test]
fn a_degenerate_window_is_still_refused_in_an_aged_record() {
    let h0 = hop_with_bad_window(CREATED, CREATED);
    assert_request_unverifiable_at_hop_0(
        &reconstruct_at(&[h0], AUDIT_LATER),
        HttpProfileError::StaleWindow,
    );
}

// --- the request EVIDENCE BLOCK, not merely the signature over it -------------

/// A hop whose block names a DIFFERENT service than the URI the request went to.
///
/// The signature says nothing about this: the block rides in the body, which is
/// covered by `content-digest`, so a request naming another audience is a perfectly
/// well-signed request. Reconstruction ran the MINIMAL proof path, which never opens
/// the block, so such a hop reconstructed as verified and the record was labelled
/// `Complete` — and a SCITT Signed Statement over it asserts a whole call record
/// containing a request the enforcement boundary would have refused with
/// `audience_mismatch`.
#[test]
fn a_hop_whose_block_names_another_target_is_not_a_verified_hop() {
    let mut elsewhere = block(None);
    elsewhere.audience = audience_named("other.example.com", "https://other.example.com/mcp");
    let hop = hop_with_block(&elsewhere, DONE);

    // Precondition: the hop is not broken. It verifies on the minimal path — the
    // one reconstruction used to run — so nothing about the signature catches this.
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&hop.request, NOW)
        .expect("the request is correctly signed; only its block is wrong");

    assert_eq!(
        reconstruct(&[hop]),
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(HttpProfileError::AudienceMismatch),
        },
    );
}

/// A hop carrying no evidence block at all. `sign_request` produces exactly this:
/// a valid RFC 9421 request with no `_meta` block, which the minimal path accepts
/// and the full profile does not.
#[test]
fn a_hop_with_no_evidence_block_is_not_a_verified_hop() {
    let mut request = unsigned_request();
    let request_evidence = sign_request(
        &mut request,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce: &unique_test_nonce(),
        },
    )
    .expect("request signs");
    let response = answer_outside_the_full_signer(&request, &request_evidence, DONE);

    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&request, NOW)
        .expect("the minimal path accepts a blockless request");

    let label = reconstruct(&[RetainedHop { request, response }]);
    match label {
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(_),
        } => {}
        other => panic!("a blockless hop must not be a verified hop, got {other:?}"),
    }
}

/// The positive control: an honest block still reconstructs, so the checks above
/// could not have been satisfied by refusing everything.
#[test]
fn an_honest_block_still_reconstructs_complete() {
    assert_eq!(
        reconstruct(&[hop_with_block(&block(None), DONE)]),
        ChainLabel::Complete
    );
}

// --- C082: the full-profile checks reconstruction used to skip -------------------

/// Audience-tuple EQUALITY, not merely "the block names the URI it was sent to".
///
/// The weaker check passed a hop whose audience named a different audience id or route
/// on the same endpoint, so a record could be attested `Complete` while containing
/// requests the enforcement boundary would have refused for the wrong audience.
#[test]
fn a_hop_whose_audience_is_not_the_verifiers_own_breaks_the_chain() {
    let mut elsewhere = block(None);
    elsewhere.audience = audience_named("other.example.com", TARGET);
    // The URI still matches, so the old target-URI-only check would have passed it.
    assert_eq!(elsewhere.audience.target_uri, audience().target_uri);
    assert_request_unverifiable_at_hop_0(
        &outcome(&[hop_with_block(&elsewhere, DONE)]),
        HttpProfileError::AudienceMismatch,
    );
}

/// A binding whose credential surface cannot be obtained fails CLOSED. Reconstruction
/// previously never looked at `artifact_bindings[]` at all, so a hop carrying a binding
/// nobody could check was indistinguishable from one carrying none.
#[test]
fn a_binding_with_no_obtainable_credential_breaks_the_chain() {
    fn nothing_available(_: &mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> {
        None
    }
    static NOTHING: fn(&mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> =
        nothing_available;
    let aud = audience();
    let starved = ChainAudit {
        expected_audience: &aud,
        artifact_material: &NOTHING,
    };
    let hops = [hop_with_block(&block(None), DONE)];
    assert_request_unverifiable_at_hop_0(
        &reconstruct_against(&hops, &starved, NOW),
        HttpProfileError::ArtifactBindingFailed,
    );
}

// --- C114: a record that verified nothing still has an identity ------------------

/// Two DIFFERENT submissions that both break at hop 0 must not produce the same record.
///
/// Every field derived from the verified prefix is empty for both — that is the defect:
/// the statements were byte-identical, so a record about one call could be presented as
/// a record about any other call that failed the same way. The submitted-bytes
/// commitment is what tells them apart.
#[test]
fn two_records_that_verified_nothing_are_still_distinguishable() {
    let mut first = block(None);
    first.audience = audience_named("first.example.com", TARGET);
    let mut second = block(None);
    second.audience = audience_named("second.example.com", TARGET);
    let a = [hop_with_block(&first, DONE)];
    let b = [hop_with_block(&second, DONE)];
    let (ra, rb) = (outcome(&a), outcome(&b));

    // Both verified nothing: the identity fields the old record had are identical.
    assert!(ra.hop_evidence().is_empty() && rb.hop_evidence().is_empty());
    assert_eq!(ra.label(), rb.label(), "they even fail the same way");

    assert_ne!(
        ra.submitted_commitment(),
        rb.submitted_commitment(),
        "two different submissions must not share one identity",
    );
    assert!(!ra.submitted_commitment().is_empty());
}

/// One named alteration of a retained hop: what it changes, and how.
///
/// A plain `fn` rather than a boxed closure because none of the alterations captures
/// anything, and named because the alternative reads as a type before it reads as a list of
/// what a hop is made of.
type HopAlteration = (&'static str, fn(&mut RetainedHop));

/// Every retained fact about a hop is part of its identity — the control that makes the
/// closed representation a claim rather than a comment.
///
/// Each case alters exactly one field of the retained hop and requires the commitment to
/// move. `signature-input` is the case that motivated the closed representation: a curated
/// field list folded `signature` and not the header that says WHAT was signed, so two
/// unverified tail hops naming different covered components shared an identity. The
/// remaining cases exist so that a future curation cannot pass this test by re-adding one
/// header.
#[test]
fn every_retained_field_of_a_hop_is_part_of_its_identity() {
    let base = hop_with_block(&block(None), r#"{"ok":true}"#);
    let identity = |h: &RetainedHop| {
        outcome(std::slice::from_ref(h))
            .submitted_commitment()
            .to_owned()
    };
    let baseline = identity(&base);

    let mutate: &[HopAlteration] = &[
        ("request method", |h| h.request.method = "PUT".into()),
        ("request target", |h| h.request.target_uri.push('x')),
        ("request body", |h| h.request.body.push(b' ')),
        ("response status", |h| h.response.status = 503),
        ("response body", |h| h.response.body.push(b' ')),
        ("a request header VALUE", |h| {
            h.request.headers[0].1.push('x')
        }),
        ("a request header NAME", |h| {
            h.request.headers[0].0.push('x')
        }),
        (
            "signature-input — the header a curated list omitted",
            |h| {
                for (name, value) in &mut h.request.headers {
                    if name.eq_ignore_ascii_case("signature-input") {
                        value.push_str(";x=1");
                    }
                }
            },
        ),
        ("a response header", |h| {
            h.response.headers.push(("x-added".into(), "1".into()));
        }),
        ("header ORDER", |h| h.request.headers.swap(0, 1)),
    ];

    for (what, apply) in mutate {
        let mut altered = base.clone();
        apply(&mut altered);
        assert_ne!(
            identity(&altered),
            baseline,
            "altering {what} left the submission identity unchanged"
        );
    }
}

/// The identity is of the SUBMISSION, so it is stable across runs of the same bytes —
/// otherwise it could not be compared by anyone but the process that computed it.
#[test]
fn the_submitted_identity_is_a_function_of_the_bytes_alone() {
    let hops = [hop_with_block(&block(None), DONE)];
    let run = || outcome(&hops).submitted_commitment().to_owned();
    assert_eq!(run(), run());
    // And an empty chain, which verifies nothing and has no hops at all, still gets one.
    let empty = outcome(&[]);
    assert!(!empty.submitted_commitment().is_empty());
    assert_ne!(empty.submitted_commitment(), run());
}
