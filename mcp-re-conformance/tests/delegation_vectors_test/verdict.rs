// SPDX-License-Identifier: Apache-2.0
//! The frozen runner's verdict for one fixture, black-box through the verifier.

use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::material::recompute_verified_request;
use super::material::resolver;
use super::schema::Fixture;

fn as_strs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

/// `verify_ok` or the exact `mcp-re.*` wire code the verifier refuses with.
pub(super) fn run_fixture(fixture: &Fixture, verify_at: i64) -> String {
    let request = fixture.request();
    let response = fixture.response();
    let _verified_req = recompute_verified_request(&request);

    let check = &fixture.check;
    let auds = as_strs(&check.verifier_audiences);
    let epochs = as_strs(&check.accepted_epochs);
    let expect = DelegationExpectations {
        verifier_audiences: &auds,
        expected_audience_hash: &check.expected_audience_hash,
        accepted_epochs: &epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(check.max_clock_skew)
            .expect("the fixture skew is inside the bound"),
    };
    let is_revoked = |kid: &str| check.revoked_kids.iter().any(|r| r == kid);

    match Verifier::new(&VerifierPolicy::default(), &resolver()).verify_delegated_bound_response(
        &response,
        &request,
        &expect,
        &is_revoked,
        verify_at,
    ) {
        Ok(_) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}
