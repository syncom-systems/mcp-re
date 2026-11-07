// SPDX-License-Identifier: Apache-2.0
//! The two legs' verdicts: what a verified response must be for the proof to hold.

use mcp_re_core::McpReError;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedDelegatedMcpResponse;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use crate::body::{body_wire_code, is_error_body, mcp_result};
use crate::hpp_common;

/// Print `message` and fail the proof.
fn fail(message: &str) -> ! {
    println!("{message}");
    std::process::exit(1)
}

/// What a response is verified against: the request it must be bound to, the delegation the
/// client expects, and how signers are resolved.
pub struct Verification<'a> {
    pub resolver: &'a dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    pub request: &'a HttpRequest,
    pub expect: &'a DelegationExpectations<'a>,
}

impl Verification<'_> {
    /// Verify `resp` through the DELEGATED path, against CURRENT time: its
    /// `created`/`expires` freshness is stamped by the server when it replies, which is
    /// necessarily after the `now` captured for signing — reusing the stale `now` would
    /// spuriously reject a response created "in the future" relative to it.
    ///
    /// No delegated key is revoked in the proof; a real client resolves this from its
    /// revocation source.
    fn verify(
        &self,
        resp: &HttpResponse,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        Verifier::new(&VerifierPolicy::default(), self.resolver).verify_delegated_bound_response(
            resp,
            self.request,
            self.expect,
            &|_kid: &str| false,
            hpp_common::now_unix(),
        )
    }

    /// Leg 1: the reply is server-signed, bound to THIS request, and a success.
    pub fn accept_happy_path(&self, resp: &HttpResponse) {
        match self.verify(resp) {
            // A signed rejection ALSO verifies as a bound response, so distinguish a
            // success (`result`) from a fail-closed receipt (`error`) on the trusted body.
            Ok(_) if is_error_body(&resp.body) => fail(&format!(
                "leg 1  UNEXPECTED signed rejection  status={}  wire_code={}",
                resp.status,
                body_wire_code(&resp.body).unwrap_or_default()
            )),
            Ok(verified) => println!(
                "leg 1  ACCEPTED  server_signer={}  status={}  fastmcp_result={}",
                verified.signature_facts().accepted_signer.identity.subject,
                resp.status,
                mcp_result(&resp.body)
            ),
            Err(e) => fail(&format!(
                "leg 1  UNEXPECTED verify failure: {}",
                e.wire_code()
            )),
        }
    }

    /// Leg 2: a DELEGATED rejection receipt is verified through the SAME delegated path as
    /// an answer — it is signed by the delegated key and carries the same credential, so
    /// the refusal is as verifiable as an acceptance.
    ///
    /// Verifying only proves the receipt is authentic and bound to THIS request; whether
    /// it is an acceptance is then read from the trusted body.
    pub fn reject_replay(&self, resp: &HttpResponse) {
        match self.verify(resp) {
            Ok(_) if is_error_body(&resp.body) => self.expect_replay_code(resp),
            Ok(_) => fail("leg 2  UNEXPECTED: replay was ACCEPTED"),
            Err(e) => fail(&format!(
                "leg 2  UNEXPECTED: rejection did not verify: {}",
                e.wire_code()
            )),
        }
    }

    fn expect_replay_code(&self, resp: &HttpResponse) {
        let wire_code = body_wire_code(&resp.body).unwrap_or_default();
        println!(
            "leg 2  REJECTED  delegated rejection verified  status={}  wire_code={}",
            resp.status, wire_code
        );
        if wire_code != McpReError::ReplayDetected.wire_code() {
            fail("leg 2  WARNING: expected mcp-re.replay_detected");
        }
    }
}
