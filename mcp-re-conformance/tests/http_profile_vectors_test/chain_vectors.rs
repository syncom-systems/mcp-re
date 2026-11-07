// SPDX-License-Identifier: Apache-2.0
//! Retained-chain vectors (#416 rev 2 §9/§13, MCPRE-430/431).
//!
//! The continuation vectors check ONE handle set in isolation. These check what §9
//! actually requires: that a whole chain re-links. Each freezes complete signed messages
//! per hop, so a third party replays real evidence rather than this project's opinion of
//! a handle.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::block::AudienceTuple;
use mcp_re_http_profile::custody::ActiveDelegatedKey;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::RequestSignature;
use mcp_re_http_profile::ResponseRoleEvidence;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::delegation::issue_credential;
use super::delegation::server_signer;
use super::delegation::Grant;
use super::material::client_key;
use super::material::post;
use super::material::resolver;
use super::material::server_key;
use super::material::CLIENT_KEY_ID;
use super::material::CREATED;
use super::material::EXPIRES;
use super::material::JSON;
use super::material::MCP_ENDPOINT;
use super::material::NOW;
use super::material::READ_CALL;
use super::material::SERVER_KEY_ID;
use super::schema::to_wire_request;
use super::schema::to_wire_response;
use super::schema::ChainCheck;
use super::schema::ChainHop;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

/// What a hop's response says about whether its turn ended.
#[derive(Clone, Copy)]
enum Body {
    /// A turn still awaiting input.
    Awaiting,
    /// A terminal result.
    Done,
    /// A result type outside the set MCP 2026-07-28 defines and this implementation
    /// advertises. Not malformed — a well-formed message this reader cannot classify.
    Unrecognized,
}

impl Body {
    fn json(self) -> &'static str {
        match self {
            Body::Awaiting => {
                r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#
            }
            Body::Done => r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
            Body::Unrecognized => {
                r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#
            }
        }
    }
}

/// The delegated key every chain hop's response is signed with, and the root-signed
/// credential that authorizes it.
const DELEGATED_KID: &str = "server-key-1/delegated/1";
const AUDIENCE: &str = "did:example:server";
const AUDIENCE_HASH: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[66u8; 32])
}

fn credential() -> String {
    issue_credential(&Grant {
        issuer: &server_key(),
        issuer_kid: SERVER_KEY_ID,
        delegated: &delegated_key(),
        delegated_kid: DELEGATED_KID,
        jti: "evt-chain",
        audience: AUDIENCE,
        audience_hash: AUDIENCE_HASH,
        epoch: EPOCH,
    })
}

pub(super) fn chain_expectations() -> mcp_re_http_profile::DelegationExpectations<'static> {
    mcp_re_http_profile::DelegationExpectations {
        verifier_audiences: &[AUDIENCE],
        expected_audience_hash: AUDIENCE_HASH,
        accepted_epochs: &[EPOCH],
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    }
}

pub(super) fn chain_nothing_revoked(_: &str) -> bool {
    false
}

fn chain_audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "mcp.example.com".into(),
        target_uri: MCP_ENDPOINT.into(),
        route: Some("tools/call".into()),
    }
}

fn chain_block(continuation: Option<HttpContinuation>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: mcp_re_http_profile::PROFILE_TAG.into(),
        audience: chain_audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    }
}

/// One signed hop with the two role-labeled handles the next hop's continuation must name.
struct Hop {
    retained: RetainedHop,
    request_evidence: RequestRoleEvidence,
    response_evidence: ResponseRoleEvidence,
}

fn sign_request_hop(
    nonce: &str,
    continuation: Option<HttpContinuation>,
) -> (HttpRequest, RequestRoleEvidence) {
    // The DPoP `ath` binding commits to the bearer token in the covered
    // `Authorization` header, and only there.
    let mut request = post(&[("Authorization", "Bearer tok")], READ_CALL);
    let evidence = sign_request_full(
        &mut request,
        &chain_block(continuation),
        &client_key(),
        &RequestSignature {
            key_id: CLIENT_KEY_ID,
            created: CREATED,
            expires: EXPIRES,
            nonce,
        },
    )
    .expect("request signs");
    (request, evidence)
}

fn sign_response_hop(request: &HttpRequest, body: Body) -> (HttpResponse, ResponseRoleEvidence) {
    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), JSON.into())],
        body: body.json().as_bytes().to_vec(),
    };
    // DELEGATED signing, because that is the only response mode the serving path has.
    // Signing these hops direct-root meant the frozen corpus exercised a mode removed
    // from the runtime surface, so a green suite said nothing about real evidence.
    sign_delegated_response_full(
        &mut response,
        request,
        &SigningWindow::stated(
            ActiveDelegatedKey::stated(
                delegated_key(),
                server_signer(DELEGATED_KID),
                credential(),
                DELEGATED_KID,
            ),
            CREATED,
            EXPIRES,
        ),
    )
    .expect("response signs");
    let evidence = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &response,
            request,
            &chain_expectations(),
            &chain_nothing_revoked,
            NOW,
        )
        .expect("response verifies")
        .signature_facts()
        .response_signature_base_digest
        .clone();
    (response, evidence)
}

fn hop(nonce: &str, continuation: Option<HttpContinuation>, body: Body) -> Hop {
    let (request, request_evidence) = sign_request_hop(nonce, continuation);
    let (response, response_evidence) = sign_response_hop(&request, body);
    Hop {
        retained: RetainedHop { request, response },
        request_evidence,
        response_evidence,
    }
}

/// The continuation a hop following `previous` presents, carrying `state`.
fn continuing(previous: &Hop, state: &[u8]) -> HttpContinuation {
    HttpContinuation::from_handles(
        previous.request_evidence.to_digest(),
        previous.response_evidence.to_digest(),
        state,
    )
}

/// A first hop answering `first_body`, followed by a hop continuing it and answering
/// `last_body`.
fn pair(tag: &str, first_body: Body, state: &[u8], last_body: Body) -> Vec<RetainedHop> {
    let first = hop(&format!("chain-{tag}0"), None, first_body);
    let second = hop(
        &format!("chain-{tag}1"),
        Some(continuing(&first, state)),
        last_body,
    );
    vec![first.retained, second.retained]
}

fn to_chain_hop(h: &RetainedHop) -> ChainHop {
    ChainHop {
        request: to_wire_request(&h.request),
        response: to_wire_response(&h.response),
    }
}

fn chain_fixture(name: &str, hops: &[RetainedHop], label: &str) -> Fixture {
    Fixture {
        chain_check: Some(ChainCheck {
            hops: hops.iter().map(to_chain_hop).collect(),
            expected_label: label.into(),
            expected_audience: chain_audience(),
            artifact_material_b64: Some(mcp_re_core::b64url_encode(b"tok")),
        }),
        ..Vector {
            name,
            kind: Kind::Chain,
            expected: "verify_ok",
        }
        .blank()
    }
}

/// The full three-hop chain R0→S0→R1→S1→R2→S2 the chain fixtures are cut from.
fn three_hop() -> Vec<RetainedHop> {
    let h0 = hop("chain-n0", None, Body::Awaiting);
    let h1 = hop(
        "chain-n1",
        Some(continuing(&h0, b"state-0")),
        Body::Awaiting,
    );
    let h2 = hop("chain-n2", Some(continuing(&h1, b"state-1")), Body::Done);
    vec![h0.retained, h1.retained, h2.retained]
}

/// h27 — a continuation naming ANOTHER chain's evidence (§13.2 "response from another
/// chain"): well-formed handles that do not describe this record.
fn foreign_continuation() -> Vec<RetainedHop> {
    let first = hop("chain-other0", None, Body::Awaiting);
    let source = hop("chain-other-src", None, Body::Awaiting);
    let second = hop(
        "chain-other1",
        Some(continuing(&source, b"state-o")),
        Body::Done,
    );
    vec![first.retained, second.retained]
}

/// h28 — role substitution (§7.3): the previous RESPONSE handle presented as the
/// previous-REQUEST handle and vice versa. Domain separation makes the lifted handles
/// different values in the wrong role, so re-linking rejects.
fn role_swapped() -> Vec<RetainedHop> {
    let first = hop("chain-swap0", None, Body::Awaiting);
    let swapped = HttpContinuation::from_handles(
        first.response_evidence.to_digest(),
        first.request_evidence.to_digest(),
        b"state-s",
    );
    let second = hop("chain-swap1", Some(swapped), Body::Done);
    vec![first.retained, second.retained]
}

/// h24–h29 and h51: a chain that re-links whole, then each way a retained record can fail
/// to — naming the hop that broke it.
pub(super) fn chain_fixtures() -> Vec<Fixture> {
    let full = three_hop();
    let linking_failure = "incomplete:1:continuation_does_not_link";

    vec![
        // h24 — multi-hop positive (§13.4 "multi-hop" claim): two consecutive
        // non-terminal turns followed by a terminal one, every hop re-linking.
        chain_fixture("h24_chain_multi_hop_complete", &full, "complete"),
        // h25 — the missing MIDDLE hop (§9.1/§9.3). Every retained message verifies
        // on its own and S2 is a genuine terminal result; the record is still
        // incomplete, and says so naming hop 1. This is the case §9 exists for.
        chain_fixture(
            "h25_chain_missing_middle_hop_incomplete",
            &[full[0].clone(), full[2].clone()],
            linking_failure,
        ),
        // h26 — truncated chain (§13.2): the record stops on a turn still awaiting
        // input. Every hop verifies; the call has no ending.
        chain_fixture(
            "h26_chain_truncated_incomplete",
            &full[..2],
            "incomplete:1:terminal_expected",
        ),
        chain_fixture(
            "h27_chain_foreign_continuation_incomplete",
            &foreign_continuation(),
            linking_failure,
        ),
        chain_fixture(
            "h28_chain_role_swapped_handles_incomplete",
            &role_swapped(),
            linking_failure,
        ),
        // h29 — terminal spliced onto a continuation request (§13.2): the chain
        // claims to continue past a turn that already answered terminally.
        chain_fixture(
            "h29_chain_terminal_spliced_incomplete",
            &pair("term", Body::Done, b"state-t", Body::Done),
            "incomplete:0:non_terminal_expected",
        ),
        // h51 — a hop declaring a `resultType` nobody recognizes (MCPRE-495). Every
        // message verifies and re-links; what is unknown is whether that turn ENDED.
        // Labeling it terminal would let this two-hop record read as COMPLETE on a
        // value no reader could interpret — the laundering §9.3 forbids — so the
        // record names hop 1 instead of guessing.
        chain_fixture(
            "h51_chain_unrecognized_result_type_incomplete",
            &pair("unrec", Body::Awaiting, b"state-u", Body::Unrecognized),
            "incomplete:1:unrecognized_result_type",
        ),
    ]
}
