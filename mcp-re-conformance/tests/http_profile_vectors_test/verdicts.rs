// SPDX-License-Identifier: Apache-2.0
//! The frozen runner's verdict for each fixture kind: every committed fixture is
//! replayed black-box through the verifier, and the verdict it reaches is compared with
//! the one frozen in the fixture.

use mcp_re_http_profile::authoritative_admission::AuthoritativeAdmission;
use mcp_re_http_profile::bodyless::pre_052_fixtures::verify_pre_052_root_signed_202_for_negative_test;
use mcp_re_http_profile::evidence::EvidenceRole;
use mcp_re_http_profile::reconstruct_chain;
use mcp_re_http_profile::rejection::pre_052_direct_root_verifier::verify_pre_052_direct_root_rejection_for_negative_test;
use mcp_re_http_profile::verify_artifact_binding;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use super::admission_vectors::admission_presenter;
use super::admission_vectors::ISSUER_KID;
use super::chain_vectors::chain_expectations;
use super::chain_vectors::chain_nothing_revoked;
use super::delegated_202_vectors::DELEGATED_KID;
use super::material::header_value;
use super::material::resolver;
use super::material::Header;
use super::schema::base64_std_decode;
use super::schema::from_wire_request;
use super::schema::from_wire_response;
use super::schema::AdmissionCheck;
use super::schema::Delegated202Check;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Oracle;

/// Replays one fixture at the frozen instant and returns the verdict it reached.
type Replay = fn(&Fixture, i64) -> String;

fn replay_of(kind: Kind) -> Replay {
    match kind {
        Kind::Request => replay_request,
        Kind::Response => replay_response,
        Kind::Artifact => replay_artifact,
        Kind::Continuation => replay_continuation,
        Kind::Bodyless202 => replay_bodyless_202,
        Kind::Delegated202 => replay_delegated_202,
        Kind::Admission => replay_admission,
        Kind::TransportRequest => replay_transport_request,
        Kind::Chain => replay_chain,
        Kind::Rejection => replay_rejection,
    }
}

/// The verdict the verifier reaches for `fixture`.
pub(super) fn observed(fixture: &Fixture, verify_at: i64) -> String {
    replay_of(fixture.kind)(fixture, verify_at)
}

/// A successful verification is `verify_ok`; a refusal is the wire code it carried.
fn verdict<T>(result: Result<T, HttpProfileError>) -> String {
    match result {
        Ok(_) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}

fn request_of(fixture: &Fixture) -> HttpRequest {
    from_wire_request(fixture.request.as_ref().expect("request"))
}

fn response_of(fixture: &Fixture) -> HttpResponse {
    from_wire_response(fixture.response.as_ref().expect("response"))
}

/// Oracle byte-equality (S8: assert bytes, not prints).
fn assert_oracle(
    fixture: &Fixture,
    request: &HttpRequest,
    replayed: (&str, &[u8]),
    oracle: &Oracle,
) {
    let name = &fixture.name;
    assert_eq!(
        replayed.0, oracle.request_evidence_digest_value,
        "{name}: evidence handle drifted from frozen oracle"
    );
    assert_eq!(
        mcp_re_core::b64url_encode(replayed.1),
        oracle.signature_base_b64url,
        "{name}: the reconstructed signature base drifted from the frozen oracle"
    );
    assert_eq!(
        header_value(request, Header::ContentDigest),
        oracle.content_digest,
        "{name}: digest drifted"
    );
    assert_eq!(
        header_value(request, Header::Signature),
        oracle.signature_header,
        "{name}: signature drifted"
    );
}

fn replay_request(fixture: &Fixture, verify_at: i64) -> String {
    let request = request_of(fixture);
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&request, verify_at);
    if let (Ok(verified), Some(oracle)) = (&verified, &fixture.oracle) {
        let replayed = (
            verified.evidence().digest_value(),
            verified.request_signature_base(),
        );
        assert_oracle(fixture, &request, replayed, oracle);
    }
    verdict(verified)
}

fn replay_response(fixture: &Fixture, verify_at: i64) -> String {
    verdict(
        Verifier::new(&VerifierPolicy::default(), &resolver()).verify_bound_response_floor(
            &response_of(fixture),
            &request_of(fixture),
            verify_at,
        ),
    )
}

fn replay_artifact(fixture: &Fixture, _verify_at: i64) -> String {
    let check = fixture.artifact_check.as_ref().expect("artifact_check");
    let binding: ArtifactBinding =
        serde_json::from_value(check.binding.clone()).expect("binding parses");
    verdict(verify_artifact_binding(
        &binding,
        &base64_std_decode(&check.credential_b64),
    ))
}

fn replay_continuation(fixture: &Fixture, _verify_at: i64) -> String {
    let check = fixture
        .continuation_check
        .as_ref()
        .expect("continuation_check");
    let continuation: HttpContinuation =
        serde_json::from_value(check.continuation.clone()).expect("continuation parses");
    // The vector states the bases; the verifier compares the handles a store
    // retains for them, minted under their role labels.
    let handle = |role: EvidenceRole, b64: &str| {
        mcp_re_http_profile::RequestEvidenceDigest::over_labeled(role, &base64_std_decode(b64))
    };
    verdict(continuation.verify(
        &handle(EvidenceRole::Request, &check.previous_request_base_b64),
        &handle(
            EvidenceRole::Response,
            &check.input_required_response_base_b64,
        ),
        &base64_std_decode(&check.request_state_b64),
    ))
}

fn replay_bodyless_202(fixture: &Fixture, verify_at: i64) -> String {
    verdict(verify_pre_052_root_signed_202_for_negative_test(
        &response_of(fixture),
        &request_of(fixture),
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        verify_at,
    ))
}

/// Trust seam resolving only the ROOT key, for the Response slot.
fn root_resolver(check: &Delegated202Check) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let root_key = mcp_re_core::VerificationKey::from_b64url(&check.root_public_key_b64url)
        .expect("root key parses");
    let root_kid = check.root_kid.clone();
    move |kid: &str, slot: SignerSlot| {
        (kid == root_kid && slot == SignerSlot::Response).then(|| ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: kid.into(),
            },
            verification_key: root_key.clone(),
            slot,
        })
    }
}

fn replay_delegated_202(fixture: &Fixture, verify_at: i64) -> String {
    let check = fixture
        .delegated_202_check
        .as_ref()
        .expect("delegated_202_check");
    let resolve = root_resolver(check);
    let auds = [check.verifier_audience.as_str()];
    let epochs = [check.epoch.as_str()];
    let expect = mcp_re_http_profile::DelegationExpectations {
        verifier_audiences: &auds,
        expected_audience_hash: &check.audience_hash,
        accepted_epochs: &epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    };
    let revoked = check.revoked;
    let is_revoked = move |id: &str| revoked && id == DELEGATED_KID;
    verdict(mcp_re_http_profile::verify_delegated_accepted_202(
        &from_wire_response(&check.response),
        &from_wire_request(&check.request),
        &Verifier::new(&VerifierPolicy::default(), &resolve),
        &expect,
        &is_revoked,
        verify_at,
    ))
}

fn admission_status(name: &str, status: &str) -> AdmissionStatus {
    match status {
        "admitted" => AdmissionStatus::Admitted,
        "suspended" => AdmissionStatus::Suspended,
        "revoked" => AdmissionStatus::Revoked,
        other => panic!("{name}: unknown status {other}"),
    }
}

/// The fixture states the authority's generation and status and no subject, because a
/// vector describes ONE workload: the lookup it models is the lookup for the workload
/// the call was authenticated as, so that id is the honest subject to build the state
/// with. A vector wanting to exercise a mismatched subject would have to say so, and
/// none does.
fn authoritative_state(
    fixture: &Fixture,
    check: &AdmissionCheck,
    admission_id: &str,
) -> Option<AuthoritativeAdmission> {
    let (Some(generation), Some(status)) =
        (&check.authoritative_generation, &check.authoritative_status)
    else {
        return None;
    };
    Some(AuthoritativeAdmission::new(
        admission_id.to_owned(),
        *generation,
        admission_status(&fixture.name, status),
    ))
}

fn replay_admission(fixture: &Fixture, verify_at: i64) -> String {
    let check = fixture.admission_check.as_ref().expect("admission_check");
    let binding: mcp_re_http_profile::AdmissionBinding =
        serde_json::from_value(check.binding.clone()).expect("binding parses");
    let issuer_key = mcp_re_core::VerificationKey::from_b64url(&check.issuer_public_key_b64url)
        .expect("issuer key parses");
    let policy = mcp_re_http_profile::AdmissionPolicy {
        allow_degraded_mode: check.allow_degraded_mode,
        degraded_propagation_bound: check.degraded_propagation_bound,
        ..mcp_re_http_profile::AdmissionPolicy::default()
    };
    let outcome = mcp_re_http_profile::authenticate_admission(
        &binding,
        &check.assertion_jws,
        &admission_presenter(),
        mcp_re_http_profile::PROFILE_TAG,
        &["mcp.example.com"],
        &policy,
        verify_at,
        |kid: &str| (kid == ISSUER_KID).then(|| issuer_key.clone()),
    )
    .and_then(|authenticated| {
        let authoritative = authoritative_state(fixture, check, authenticated.admission_id());
        mcp_re_http_profile::check_admission(
            authenticated,
            authoritative.as_ref(),
            &policy,
            verify_at,
        )
    });
    verdict(outcome)
}

fn replay_transport_request(fixture: &Fixture, verify_at: i64) -> String {
    // The strict 2026-07-28 contract these fixtures were built under.
    let policy = VerifierPolicy::default().with_mcp_transport(
        mcp_re_http_profile::McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]),
    );
    verdict(
        Verifier::new(&policy, &resolver()).verify_request_floor(&request_of(fixture), verify_at),
    )
}

/// The runner's label encoding, mirroring `expected_label` in the fixture.
fn label_token(label: &ChainLabel) -> String {
    match label {
        ChainLabel::Complete => "complete".to_owned(),
        ChainLabel::Incomplete { hop, reason } => {
            format!("incomplete:{hop}:{}", reason_token(reason))
        }
    }
}

fn reason_token(reason: &IncompleteReason) -> &'static str {
    match reason {
        IncompleteReason::RequestUnverifiable(_) => "request_unverifiable",
        IncompleteReason::ResponseUnverifiable(_) => "response_unverifiable",
        IncompleteReason::MissingContinuation => "missing_continuation",
        IncompleteReason::ContinuationDoesNotLink => "continuation_does_not_link",
        IncompleteReason::NonTerminalExpected => "non_terminal_expected",
        IncompleteReason::TerminalExpected => "terminal_expected",
        IncompleteReason::EmptyChain => "empty_chain",
        IncompleteReason::HopAfterAuditInstant => "hop_after_audit_instant",
        IncompleteReason::UnrecognizedResultType => "unrecognized_result_type",
    }
}

fn replay_chain(fixture: &Fixture, verify_at: i64) -> String {
    let check = fixture.chain_check.as_ref().expect("chain_check");
    let hops: Vec<RetainedHop> = check
        .hops
        .iter()
        .map(|h| RetainedHop {
            request: from_wire_request(&h.request),
            response: from_wire_response(&h.response),
        })
        .collect();
    let material = check
        .artifact_material_b64
        .as_ref()
        .map(|m| mcp_re_core::b64url_decode(m).expect("artifact material b64url"));
    let material_fn = |_: &ArtifactBinding| material.clone();
    let out = reconstruct_chain(
        &hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &chain_expectations(),
        &mcp_re_http_profile::ChainAudit {
            expected_audience: &check.expected_audience,
            artifact_material: &material_fn,
        },
        &chain_nothing_revoked,
        verify_at,
    );
    // The label IS the frozen verdict: an incomplete record must name
    // the hop that broke it, so the comparison covers WHICH hop too.
    assert_eq!(
        label_token(out.label()),
        check.expected_label,
        "{}: chain label drifted from the frozen expectation",
        fixture.name
    );
    "verify_ok".to_owned()
}

fn replay_rejection(fixture: &Fixture, verify_at: i64) -> String {
    // A rejection carries request context only when bound.
    let request = fixture.request.as_ref().map(from_wire_request);
    // On success the observed verdict IS the trusted wire code (not just "verify_ok"):
    // the frozen fixture pins the exact machine signal a client would act on.
    match verify_pre_052_direct_root_rejection_for_negative_test(
        &response_of(fixture),
        request.as_ref(),
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        verify_at,
    ) {
        Ok(wire_code) => wire_code,
        Err(e) => e.wire_code().to_owned(),
    }
}
