// SPDX-License-Identifier: Apache-2.0
//! The continuation protocol from the client's side: open a leg on one replica, hold the
//! handles, and sign the answer leg that binds to them.

use std::sync::OnceLock;

use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidenceDigest;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_test_paths::unique_test_nonce;

use super::harness::first_actor;
use super::harness::http_response;
use super::harness::served_of;
use super::harness::signed_request;
use super::harness::signed_request_as;
use super::harness::verified_reply_handle;
use super::harness::verify_request;
use super::harness::Actor;
use super::harness::NOW;
use super::harness::OPEN_BODY;
use super::replies::assert_status;
use super::replies::request_state_of;

/// The nonce of the one open request `open_on` and [`OpenLeg::unopened`] both sign, so the
/// digests the second recomputes are the ones the open leg produced. Drawn once per process.
fn open_nonce() -> &'static str {
    static OPEN_NONCE: OnceLock<String> = OnceLock::new();
    OPEN_NONCE.get_or_init(unique_test_nonce)
}

pub(super) fn answer_body(request_state: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"confirm_action","arguments":{{}},"inputResponses":{{"confirm":true}},"requestState":"{request_state}"}}}}"#
    )
    .into_bytes()
}

/// An open leg as the CLIENT holds it: the requestState, and the two evidence digests the
/// answer leg binds to — its own request handle and the response handle.
pub(super) struct OpenLeg {
    prev: RequestEvidenceDigest,
    irr: RequestEvidenceDigest,
    pub(super) state: String,
}

impl OpenLeg {
    /// The handles an open leg on the fixed open request would give, WITHOUT a store side
    /// effect — used to build a continuation whose store entry is absent. The digests are
    /// deterministic functions of the fixed open request, so any consistent handles suffice.
    pub(super) fn unopened(request_state: &str) -> Self {
        let (_req, open_ev) = signed_request(open_nonce(), OPEN_BODY, None);
        let d = open_ev.to_digest();
        Self {
            prev: d.clone(),
            irr: d,
            state: request_state.to_owned(),
        }
    }

    /// The genuine continuation over this leg's handles (exactly
    /// `HttpContinuation::from_handles`).
    pub(super) fn continuation(&self) -> HttpContinuation {
        HttpContinuation::from_handles(self.prev.clone(), self.irr.clone(), self.state.as_bytes())
    }

    /// A well-formed continuation whose digests are wrong — the same shape a client hits
    /// after losing track of which response it is answering.
    pub(super) fn mismatched_continuation(&self) -> HttpContinuation {
        HttpContinuation::from_handles(self.prev.clone(), self.prev.clone(), self.state.as_bytes())
    }

    fn signed_answer(
        &self,
        actor: &Actor,
        wire_state: &str,
        continuation: HttpContinuation,
    ) -> HttpRequest {
        signed_request_as(
            actor,
            &unique_test_nonce(),
            &answer_body(wire_state),
            Some(continuation),
        )
        .0
    }

    /// The genuine answer, signed by the actor that opened the leg.
    pub(super) fn answer(&self) -> HttpRequest {
        self.answer_with(self.continuation())
    }

    pub(super) fn answer_with(&self, continuation: HttpContinuation) -> HttpRequest {
        self.signed_answer(&first_actor(), &self.state, continuation)
    }

    /// The genuine answer, signed by a different verified actor.
    pub(super) fn answer_as(&self, actor: &Actor) -> HttpRequest {
        self.signed_answer(actor, &self.state, self.continuation())
    }

    /// The continuation is built over the GENUINE state, but the wire request carries
    /// `wire_state` in its params.
    pub(super) fn answer_carrying(&self, wire_state: &str) -> HttpRequest {
        self.signed_answer(&first_actor(), wire_state, self.continuation())
    }
}

/// One served exchange the client has fully verified.
pub(super) struct Exchange {
    evidence: RequestRoleEvidence,
    pub(super) reply: HttpResponse,
    reply_handle: RequestEvidenceDigest,
}

impl Exchange {
    /// The continuation a following leg presents to answer this exchange's reply.
    pub(super) fn continuation(&self, state: &str) -> HttpContinuation {
        HttpContinuation::from_handles(
            self.evidence.to_digest(),
            self.reply_handle.clone(),
            state.as_bytes(),
        )
    }
}

/// Sign-and-serve `signed` on `proxy`, requiring a 200 (`served_what` says what that
/// proves) and verifying both the client's request and the delegated reply.
pub(super) async fn exchange(
    proxy: &HttpProfileProxy,
    signed: (HttpRequest, RequestRoleEvidence),
    served_what: &str,
) -> Exchange {
    let (request, evidence) = signed;
    verify_request(&request);
    let served = proxy.handle(served_of(&request), NOW).await;
    assert_status(&served, 200, served_what);
    let reply = http_response(served);
    let reply_handle = verified_reply_handle(&reply, &request);
    Exchange {
        evidence,
        reply,
        reply_handle,
    }
}

/// Drive the OPEN leg on `proxy`: sign + serve + verify the `InputRequiredResult`, and
/// return the leg the answer binds to. This is exactly what the SDK/proof-client does on
/// `--save-cont`.
pub(super) async fn open_on(proxy: &HttpProfileProxy, request_state: &str) -> OpenLeg {
    let open = signed_request(open_nonce(), OPEN_BODY, None);
    let opened = exchange(proxy, open, "open leg served an InputRequiredResult").await;
    // The reply carries the opaque requestState the answer leg re-presents.
    let seen_state =
        request_state_of(&opened.reply.body).expect("open reply carries a requestState");
    assert_eq!(seen_state, request_state);
    OpenLeg {
        prev: opened.evidence.to_digest(),
        irr: opened.reply_handle,
        state: seen_state,
    }
}
