// SPDX-License-Identifier: Apache-2.0
//! Running reconstruction over a record, and the assertions the battery repeats.

use mcp_re_http_profile::reconstruct_chain;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::ChainReconstruction;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::fixtures::{audit, expectations, nothing_revoked, resolver, NOW};

/// Reconstruct `hops` as an auditor whose clock reads `now`, against `audit`.
pub fn reconstruct_against(
    hops: &[RetainedHop],
    audit: &ChainAudit<'_>,
    now: i64,
) -> ChainReconstruction {
    reconstruct_chain(
        hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        audit,
        &nothing_revoked,
        now,
    )
}

/// Reconstruct `hops` as an auditor whose clock reads `now`.
pub fn reconstruct_at(hops: &[RetainedHop], now: i64) -> ChainReconstruction {
    reconstruct_against(hops, &audit(), now)
}

/// Reconstruct `hops` at the live instant the fixtures are signed around.
pub fn outcome(hops: &[RetainedHop]) -> ChainReconstruction {
    reconstruct_at(hops, NOW)
}

pub fn reconstruct(hops: &[RetainedHop]) -> ChainLabel {
    outcome(hops).label().clone()
}

/// The label of `hops` must be `Incomplete` at `hop` for exactly `reason`.
pub fn assert_incomplete(hops: &[RetainedHop], hop: usize, reason: IncompleteReason) {
    assert_eq!(reconstruct(hops), ChainLabel::Incomplete { hop, reason });
}

/// Precondition for the truncation tests: they are not about broken messages. Each
/// hop verifies on its own — the record is a set of individually valid evidence.
pub fn assert_each_hop_verifies_alone(hops: &[RetainedHop]) {
    for h in hops {
        let _v = Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_request_floor(&h.request, NOW)
            .expect("the retained request verifies on its own");
        Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_delegated_bound_response(
                &h.response,
                &h.request,
                &expectations(),
                &nothing_revoked,
                NOW,
            )
            .expect("the retained response verifies and is bound to its request");
    }
}

/// The record is broken at hop 0 because the request is unverifiable for exactly `error`.
pub fn assert_request_unverifiable_at_hop_0(
    out: &ChainReconstruction,
    error: mcp_re_http_profile::HttpProfileError,
) {
    match out.label() {
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(e),
        } if *e == error => {}
        other => panic!("expected the request to be unverifiable for {error:?}, got {other:?}"),
    }
}
