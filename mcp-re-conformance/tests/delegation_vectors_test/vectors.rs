// SPDX-License-Identifier: Apache-2.0
//! The writer's source of truth: the §9 vector plan, in frozen emission order.

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestRoleEvidence;

use super::claim_vectors::claim_fixtures;
use super::claim_vectors::issuer_fixtures;
use super::credential::valid_response;
use super::key_vectors::presence_and_key_fixtures;
use super::key_vectors::rotation_and_tamper_fixtures;
use super::material::signed_request;
use super::policy_vectors::policy_fixtures;
use super::schema::wire_request;
use super::schema::DelegationCheck;
use super::schema::Fixture;
use super::schema::Verdict;
use super::schema::WireMessage;

/// The one signed request every vector answers, with the valid response to it.
pub(super) struct Case {
    pub(super) req: HttpRequest,
    pub(super) ev: RequestRoleEvidence,
    req_wire: WireMessage,
    pub(super) valid_rsp: HttpResponse,
}

impl Case {
    pub(super) fn new() -> Self {
        let (req, ev) = signed_request();
        Case {
            req_wire: wire_request(&req),
            valid_rsp: valid_response(&req),
            req,
            ev,
        }
    }

    /// A fixture that checks `rsp` under `check` and expects `expected`.
    pub(super) fn fixture(
        &self,
        verdict: Verdict,
        rsp: &HttpResponse,
        check: DelegationCheck,
    ) -> Fixture {
        Fixture::new(verdict, self.req_wire.clone(), rsp, check)
    }

    /// A fixture checked under the nominal in-policy verifier.
    pub(super) fn nominal(&self, name: &str, expected: &str, rsp: &HttpResponse) -> Fixture {
        self.fixture(Verdict { name, expected }, rsp, DelegationCheck::nominal())
    }
}

/// The whole corpus, d01–d22, in the order the writer emits it.
pub(super) fn build_fixtures() -> Vec<Fixture> {
    let case = Case::new();
    [
        claim_fixtures(&case),
        policy_fixtures(&case),
        presence_and_key_fixtures(&case),
        issuer_fixtures(&case),
        rotation_and_tamper_fixtures(&case),
    ]
    .into_iter()
    .flatten()
    .collect()
}
