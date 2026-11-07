// SPDX-License-Identifier: Apache-2.0
//! The delegated-required verifier a lane judges responses with: the KMS root public key
//! resolved by its issuer kid, and a client that is the only other enrolled key.

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::VerifiedDelegatedMcpResponse;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::fixtures::EPOCH;
use super::fixtures::VERIFIER_AUD;
use super::Lane;

/// One response and the request it answers.
#[derive(Clone, Copy)]
pub(super) struct Exchange<'a> {
    pub(super) request: &'a HttpRequest,
    pub(super) response: &'a HttpResponse,
}

/// The trust epochs accepted and the kids revoked when a response is judged.
struct Scope<'a> {
    epochs: &'a [&'a str],
    revoked: &'a dyn Fn(&str) -> bool,
}

pub(super) struct Judge<'a> {
    lane: &'a Lane,
    root_pub: VerificationKey,
}

impl<'a> Judge<'a> {
    pub(super) fn new(lane: &'a Lane, root_pub: VerificationKey) -> Self {
        Judge { lane, root_pub }
    }

    /// Judged under the base epoch with nothing revoked.
    pub(super) fn verify(
        &self,
        exchange: &Exchange<'_>,
        at: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        self.verify_under_epochs(exchange, &[EPOCH], at)
    }

    /// Judged under the accepted epoch set `epochs`, with nothing revoked.
    pub(super) fn verify_under_epochs(
        &self,
        exchange: &Exchange<'_>,
        epochs: &[&str],
        at: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        let scope = Scope {
            epochs,
            revoked: &|_| false,
        };
        self.judge(exchange, &scope, at)
    }

    /// Judged under the base epoch with the kids `revoked` names revoked.
    pub(super) fn verify_revoking(
        &self,
        exchange: &Exchange<'_>,
        revoked: &dyn Fn(&str) -> bool,
        at: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        let scope = Scope {
            epochs: &[EPOCH],
            revoked,
        };
        self.judge(exchange, &scope, at)
    }

    fn judge(
        &self,
        exchange: &Exchange<'_>,
        scope: &Scope<'_>,
        at: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        let resolver = self.lane.resolver(self.root_pub.clone());
        let expect = DelegationExpectations {
            verifier_audiences: &[VERIFIER_AUD],
            expected_audience_hash: VERIFIER_AUD,
            accepted_epochs: scope.epochs,
            max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
        };
        Verifier::new(&VerifierPolicy::default(), &resolver).verify_delegated_bound_response(
            exchange.response,
            exchange.request,
            &expect,
            scope.revoked,
            at,
        )
    }
}
