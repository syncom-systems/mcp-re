// SPDX-License-Identifier: Apache-2.0
//! Verification entry points and refusal assertions for the delegated-signing battery.

use super::fixtures::{expectations, resolver, EPOCH, NOW};
use super::signing::{signed_delegated_bound, signed_delegated_unbound};
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::VerifiedDelegatedMcpResponse;
use mcp_re_http_profile::VerifiedDelegatedUnboundResponse;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

/// What the verifier is asked: which trust epochs it accepts, which key it has revoked, when.
#[derive(Clone, Copy)]
pub struct Checks<'a> {
    pub epochs: &'a [&'a str],
    pub revoked_kid: Option<&'a str>,
    pub now: i64,
}

impl Checks<'static> {
    /// The credential's own epoch, nothing revoked, inside the signature window.
    pub const STANDARD: Checks<'static> = Checks {
        epochs: &[EPOCH],
        revoked_kid: None,
        now: NOW,
    };
}

impl<'a> Checks<'a> {
    pub fn at(self, now: i64) -> Self {
        Self { now, ..self }
    }

    fn expectations(&self) -> DelegationExpectations<'a> {
        expectations(self.epochs)
    }

    fn revoked(&self) -> impl Fn(&str) -> bool + 'a {
        let revoked_kid = self.revoked_kid;
        move |kid| revoked_kid == Some(kid)
    }
}

/// Run `verify` with a verifier over the battery's trust seam and `checks` unpacked into the
/// arguments every delegated verification takes.
fn verify_under<T>(
    checks: Checks<'_>,
    verify: impl FnOnce(
        &Verifier<'_, Option<ResolvedActor>>,
        &DelegationExpectations<'_>,
        &dyn Fn(&str) -> bool,
        i64,
    ) -> T,
) -> T {
    let policy = VerifierPolicy::default();
    let seam = resolver();
    let verifier = Verifier::new(&policy, &seam);
    verify(
        &verifier,
        &checks.expectations(),
        &checks.revoked(),
        checks.now,
    )
}

pub fn verify_bound(
    rsp: &HttpResponse,
    req: &HttpRequest,
    checks: Checks<'_>,
) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
    verify_under(checks, |v, expect, revoked, now| {
        v.verify_delegated_bound_response(rsp, req, expect, revoked, now)
    })
}

pub fn verify_unbound(
    rsp: &HttpResponse,
    checks: Checks<'_>,
) -> Result<VerifiedDelegatedUnboundResponse, HttpProfileError> {
    verify_under(checks, |v, expect, revoked, now| {
        v.verify_delegated_unbound_response(rsp, expect, revoked, now)
    })
}

/// Assert the bound delegated path refuses `rsp` with `expected`.
pub fn assert_bound_refused(
    rsp: &HttpResponse,
    req: &HttpRequest,
    checks: Checks<'_>,
    expected: HttpProfileError,
) {
    assert_eq!(verify_bound(rsp, req, checks).unwrap_err(), expected);
}

/// Assert the unbound delegated path refuses `rsp` with `expected`.
pub fn assert_unbound_refused(rsp: &HttpResponse, checks: Checks<'_>, expected: HttpProfileError) {
    assert_eq!(verify_unbound(rsp, checks).unwrap_err(), expected);
}

/// The instant after the signature window and its permitted clock skew have closed.
pub fn past_the_window() -> i64 {
    super::fixtures::EXPIRES + VerifierPolicy::default().max_clock_skew() + 1
}

/// Sign a fresh bound delegated response, damage it with `damage`, and assert the bound path
/// refuses it with `expected`.
pub fn assert_damaged_bound_refused(
    damage: impl FnOnce(&mut HttpResponse),
    expected: HttpProfileError,
) {
    let (req, mut rsp) = signed_delegated_bound();
    damage(&mut rsp);
    assert_bound_refused(&rsp, &req, Checks::STANDARD, expected);
}

/// Sign a fresh delegated preflight receipt, damage it with `damage`, and assert the unbound
/// path refuses it with `expected`.
pub fn assert_damaged_unbound_refused(
    damage: impl FnOnce(&mut HttpResponse),
    expected: HttpProfileError,
) {
    let mut rsp = signed_delegated_unbound();
    damage(&mut rsp);
    assert_unbound_refused(&rsp, Checks::STANDARD, expected);
}
