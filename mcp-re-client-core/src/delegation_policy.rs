// SPDX-License-Identifier: Apache-2.0
//! The client's delegation policy — one owner for the credential-scope inputs and the
//! clock-skew tolerance applied to both freshness windows.
//!
//! # Why this is a module and not four fields beside the verifier
//!
//! The fields are private, and in one crate the only lever that makes a private field mean
//! anything is **module privacy**: while this type lived beside `verify_delegated_response`,
//! that function could read the representation directly, so "private" bound nobody who was
//! actually going to destructure it. Here it binds every consumer, and
//! [`DelegationPolicy::with_expectations`] is the whole projection.
//!
//! It is also authority **E** of the client-response-verification blueprint, distinct from
//! delegated response verification itself: *what the credential must satisfy* is not *is
//! this response a genuine delegated answer*.

use mcp_re_core::MaxClockSkew;
use mcp_re_http_profile::DelegationExpectations;

/// The deployment policy the client applies when verifying a DELEGATED-key-signed
/// response (ADR-MCPRE-052 §3) — the owned, client-side mirror of
/// [`mcp_re_http_profile::DelegationExpectations`]. The trusted ROOT issuer is
/// injected through the actor resolver (the credential's `issuer_kid` resolved for
/// the `Response` slot); this carries the audience-scope, epoch, and skew policy the
/// credential must satisfy.
/// # Why every field is private
///
/// They are the policy's representation, and the two verification entry points below used
/// to destructure all four to build a [`DelegationExpectations`] apiece: two copies of one
/// mapping, which is how one of them ends up with a stale field.
/// [`with_expectations`](Self::with_expectations) is the single projection, so there is one
/// place where this policy becomes the profile's expectations and one place where the skew
/// reaches both windows.
#[derive(Debug, Clone)]
pub struct DelegationPolicy {
    /// This client's accepted verifier audience identifier(s); the credential's
    /// `aud` must name one.
    verifier_audiences: Vec<String>,
    /// The audience-scope hash the delegated key must be scoped to (the request's
    /// audience hash the deployment coordinates).
    expected_audience_hash: String,
    /// The accepted trust-epoch set (default `{ current }`, optionally
    /// `{ current, previous }` in a bounded rollout window).
    accepted_epochs: Vec<String>,
    /// Clock-skew tolerance. A [`MaxClockSkew`], so it is inside the profile bound by
    /// construction; an out-of-range configured value was refused where it was configured.
    ///
    /// It governs BOTH the credential's `nbf`/`exp` window and the RFC 9421
    /// response-signature freshness gate, and the two must be the same number: a
    /// deployment that widened the skew for a real clock spread and got it on one
    /// window only is running two different notions of "close enough" on one message.
    clock_skew: MaxClockSkew,
}

impl DelegationPolicy {
    /// The RFC 9421 signature-acceptance policy this delegation policy implies: the
    /// profile's own implemented algorithm set and this policy's skew, so verification never
    /// runs under a skew this policy did not carry.
    fn verifier_policy(&self) -> mcp_re_http_profile::VerifierPolicy {
        mcp_re_http_profile::VerifierPolicy::default().with_max_clock_skew(self.clock_skew)
    }

    /// Build a delegation policy. The skew is already a [`MaxClockSkew`]: the policy has no
    /// out-of-range value to decide about.
    pub fn new(
        verifier_audiences: Vec<String>,
        expected_audience_hash: impl Into<String>,
        accepted_epochs: Vec<String>,
        max_clock_skew: MaxClockSkew,
    ) -> Self {
        DelegationPolicy {
            verifier_audiences,
            expected_audience_hash: expected_audience_hash.into(),
            accepted_epochs,
            clock_skew: max_clock_skew,
        }
    }

    /// Apply `f` to the profile expectations and signature policy this policy implies.
    ///
    /// A closure rather than a return value because [`DelegationExpectations`] BORROWS
    /// `&[&str]`: the `Vec<&str>` views of the owned `Vec<String>` fields have to outlive
    /// the call, so they cannot leave this frame. Handing the built pair to a closure keeps
    /// the one destructuring of this policy inside the policy — the two verification entry
    /// points had a verbatim copy each, and the skew bound had to be remembered at both.
    ///
    /// Both halves read this policy's one skew, so the credential's `nbf`/`exp` window and
    /// the RFC 9421 freshness gate cannot be given two different notions of "close enough"
    /// for one message.
    /// `pub(crate)`, and that is the widening this owner intends: the projection IS the
    /// consumer contract. Every field stays private, so a consumer can obtain the
    /// expectations this policy implies and nothing else — it cannot reach the
    /// representation to build a different set.
    pub(crate) fn with_expectations<T>(
        &self,
        f: impl FnOnce(&DelegationExpectations<'_>, &mcp_re_http_profile::VerifierPolicy) -> T,
    ) -> T {
        let audiences: Vec<&str> = self.verifier_audiences.iter().map(String::as_str).collect();
        let epochs: Vec<&str> = self.accepted_epochs.iter().map(String::as_str).collect();
        let expect = DelegationExpectations {
            verifier_audiences: &audiences,
            expected_audience_hash: self.expected_audience_hash.as_str(),
            accepted_epochs: &epochs,
            max_clock_skew: self.clock_skew,
        };
        f(&expect, &self.verifier_policy())
    }
}

#[cfg(test)]
mod policy_seal_tests {
    use super::*;

    #[test]
    fn both_gates_read_the_one_skew_the_policy_holds() {
        // The credential window and the RFC 9421 signature window must be one number, over
        // every tolerance the type can hold.
        for secs in [0, 1, 120, MaxClockSkew::BOUND_SECS] {
            let skew = MaxClockSkew::new(secs).expect("inside the bound");
            let policy = DelegationPolicy::new(
                vec!["aud".to_owned()],
                "hash",
                vec!["epoch".to_owned()],
                skew,
            );
            let (expect_skew, verifier_skew) = policy.with_expectations(|expect, verifier| {
                (expect.max_clock_skew, verifier.max_clock_skew())
            });
            assert_eq!(expect_skew, skew);
            assert_eq!(verifier_skew, secs);
        }
    }
}
