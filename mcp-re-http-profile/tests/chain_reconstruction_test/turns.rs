// SPDX-License-Identifier: Apache-2.0
//! Signing of retained hops and the chains the battery reconstructs.

use mcp_re_http_profile::body::insert_meta_block;
use mcp_re_http_profile::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use mcp_re_http_profile::sign::sign_response_with_signer;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::HttpResponseEvidenceBlock;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResponseRoleEvidence;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_test_paths::unique_test_nonce;

use super::fixtures::{
    block, client_key, credential, delegated_key, expectations, nothing_revoked, resolver,
    server_signer, signing_window, unsigned_request, unsigned_response, AWAITING, CLIENT_KEY_ID,
    CREATED, DELEGATED_KID, DONE, EXPIRES,
};

/// A hop plus the two role-labeled handles the next hop's continuation has to name.
pub struct SignedTurn {
    pub retained: RetainedHop,
    request_evidence: RequestRoleEvidence,
    response_evidence: ResponseRoleEvidence,
}

impl SignedTurn {
    /// The continuation a following request carries to link back to this turn.
    pub fn continuation(&self, state: &[u8]) -> HttpContinuation {
        HttpContinuation::from_handles(
            self.request_evidence.to_digest(),
            self.response_evidence.to_digest(),
            state,
        )
    }

    /// The same two handles in each other's slot: a request handle presented as the
    /// response one and vice versa.
    pub fn role_swapped_continuation(&self, state: &[u8]) -> HttpContinuation {
        HttpContinuation::from_handles(
            self.response_evidence.to_digest(),
            self.request_evidence.to_digest(),
            state,
        )
    }
}

/// Sign one hop: a request (optionally continuing a previous one) and the
/// response that answers it.
pub fn hop(continuation: Option<HttpContinuation>, body: &str) -> SignedTurn {
    hop_at(CREATED, EXPIRES, continuation, body)
}

/// [`hop`] with the signing window given explicitly, for chains whose turns are
/// minted at different times — which is every real chain.
pub fn hop_at(
    created: i64,
    expires: i64,
    continuation: Option<HttpContinuation>,
    body: &str,
) -> SignedTurn {
    let mut request = unsigned_request();
    let request_evidence = sign_request_full(
        &mut request,
        &block(continuation),
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created,
            expires,
            nonce: &unique_test_nonce(),
        },
    )
    .expect("request signs");

    let response = signed_response(&request, body, created, expires);

    // The response handle the next continuation must name is the response-role
    // digest of this response's signature base — recomputed by verifying, exactly
    // as the reconstruction will. Verified at the hop's own `created`, which is
    // inside its own window whatever that window is.
    let response_evidence = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &response,
            &request,
            &expectations(),
            &nothing_revoked,
            created,
        )
        .expect("response verifies")
        .signature_facts()
        .response_signature_base_digest
        .clone();

    SignedTurn {
        retained: RetainedHop { request, response },
        request_evidence,
        response_evidence,
    }
}

/// A hop signed over a window no verifier will accept, so the handle derivation
/// [`hop_at`] performs is skipped — it would fail on the very window under test.
/// Returns only the retained messages, which is all a malformed-window case needs.
pub fn hop_with_bad_window(created: i64, expires: i64) -> RetainedHop {
    let mut request = unsigned_request();
    sign_request_full(
        &mut request,
        &block(None),
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created,
            expires,
            nonce: &unique_test_nonce(),
        },
    )
    .expect("signing does not police the window; verification does");
    let response = signed_response(&request, DONE, created, expires);
    RetainedHop { request, response }
}

/// The delegated response answering `request` over `[created, expires]`.
fn signed_response(request: &HttpRequest, body: &str, created: i64, expires: i64) -> HttpResponse {
    let mut response = unsigned_response(body);
    sign_delegated_response_full(&mut response, request, &signing_window(created, expires))
        .expect("response signs");
    response
}

/// Sign one hop with a caller-chosen evidence block, so a test can put a block in
/// the retained bytes that the enforcement boundary would have refused.
pub fn hop_with_block(blk: &HttpRequestEvidenceBlock, body: &str) -> RetainedHop {
    let mut request = unsigned_request();
    sign_request_full(
        &mut request,
        blk,
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce: &unique_test_nonce(),
        },
    )
    .expect("request signs");
    RetainedHop {
        response: signed_response(&request, body, CREATED, EXPIRES),
        request,
    }
}

/// A delegated response to `request` assembled outside the full-profile signer, which
/// refuses to answer a request carrying no valid evidence block. Same block and signature
/// shape as a full-profile answer; a reconstruction meets this from a signer that is not this
/// crate's.
pub fn answer_outside_the_full_signer(
    request: &HttpRequest,
    request_evidence: &RequestRoleEvidence,
    body: &str,
) -> HttpResponse {
    assert!(
        sign_delegated_response_full(
            &mut unsigned_response(body),
            request,
            &signing_window(CREATED, EXPIRES)
        )
        .is_err(),
        "the full-profile signer refuses to answer this request"
    );
    let mut response = unsigned_response(body);
    let block = HttpResponseEvidenceBlock {
        profile: PROFILE_TAG.into(),
        server_signer: server_signer(),
        server_delegation: Some(credential(CREATED, EXPIRES)),
        request_evidence: request_evidence.to_digest(),
    };
    response.body =
        insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block).expect("insert");
    sign_response_with_signer(
        &mut response,
        request,
        |base| {
            mcp_re_core::b64url_decode(&delegated_key().sign(base))
                .map_err(|_| HttpProfileError::InvalidSignature)
        },
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("the ;req signer binds to a request without a block");
    response
}

/// One signed turn of a chain: its window and what its response says.
pub type TurnSpec = (i64, i64, &'static str);

/// Sign each turn in order, every one continuing the one before it with the state
/// `state-<index of the turn continued>`.
pub fn chain(turns: &[TurnSpec]) -> Vec<RetainedHop> {
    let mut hops = Vec::with_capacity(turns.len());
    let mut previous: Option<(usize, SignedTurn)> = None;
    for (index, (created, expires, body)) in turns.iter().enumerate() {
        let continuation = previous
            .as_ref()
            .map(|(n, turn)| turn.continuation(format!("state-{n}").as_bytes()));
        let turn = hop_at(*created, *expires, continuation, body);
        hops.push(turn.retained.clone());
        previous = Some((index, turn));
    }
    hops
}

/// A 3-hop chain R0→S0→R1→S1→R2→S2, each hop continuing the last, ending
/// terminally. This is the multi-hop positive (#416 §13.4 "multi-hop" claim).
pub fn three_hop_chain() -> Vec<RetainedHop> {
    chain(&[
        (CREATED, EXPIRES, AWAITING),
        (CREATED, EXPIRES, AWAITING),
        (CREATED, EXPIRES, DONE),
    ])
}

/// A chain whose turns span more than one freshness window, audited long after
/// the call ended. This is what a retained record actually looks like: a human
/// answered an elicitation after lunch, and the archive is read next year.
///
/// Every fixture above signs all three hops inside ONE window bracketing `NOW`,
/// which is why none of them caught this. Reconstruction used to hand the live
/// clock to every hop's freshness check, so the moment the record aged past a
/// single window — an hour by default, and less than the gap between hop 0 and
/// hop 1 here — `Complete` became unreachable for evidence that was entirely
/// intact. The label decayed with age instead of describing the evidence, and a
/// SCITT receipt over it would have committed to `Incomplete` for a whole call.
pub fn aged_chain() -> Vec<RetainedHop> {
    // Two hours between turns, so no two hops share a window and none of them
    // contains the audit instant.
    const TURN: i64 = 7_200;
    chain(&[
        (CREATED, CREATED + 300, AWAITING),
        (CREATED + TURN, CREATED + TURN + 300, AWAITING),
        (CREATED + 2 * TURN, CREATED + 2 * TURN + 300, DONE),
    ])
}
