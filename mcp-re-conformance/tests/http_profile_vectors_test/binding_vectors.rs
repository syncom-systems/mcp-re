// SPDX-License-Identifier: Apache-2.0
//! Artifact-binding (MCPRE-95) and MRTR continuation (MCPRE-97) vectors.

use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::HttpContinuation;

use super::schema::credential_b64;
use super::schema::ArtifactCheck;
use super::schema::ContinuationCheck;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

/// One artifact vector: the credential the binding commits to, and whether the
/// credential presented at verify time is that same one.
struct ArtifactCase {
    name: &'static str,
    artifact_type: ArtifactType,
    credential: &'static [u8],
    presents_true_credential: bool,
}

const DPOP_TOKEN: &[u8] = b"dpop-access-token-abc";
const MTLS_CERT: &[u8] = b"\x30\x82fake-client-cert-der";
const RAR_DETAILS: &[u8] = br#"[{"type":"payment_initiation","actions":["initiate"]}]"#;

fn artifact_cases() -> [ArtifactCase; 6] {
    let case = |name, artifact_type, credential, presents_true_credential| ArtifactCase {
        name,
        artifact_type,
        credential,
        presents_true_credential,
    };
    [
        case(
            "h09_artifact_dpop_ath_valid",
            ArtifactType::OauthDpop,
            DPOP_TOKEN,
            true,
        ),
        case(
            "h10_artifact_dpop_ath_mismatch",
            ArtifactType::OauthDpop,
            DPOP_TOKEN,
            false,
        ),
        case(
            "h11_artifact_mtls_x5t_valid",
            ArtifactType::OauthMtls,
            MTLS_CERT,
            true,
        ),
        case(
            "h12_artifact_mtls_x5t_mismatch",
            ArtifactType::OauthMtls,
            MTLS_CERT,
            false,
        ),
        case(
            "h13_artifact_rar_digest_valid",
            ArtifactType::OauthRar,
            RAR_DETAILS,
            true,
        ),
        case(
            "h14_artifact_rar_digest_mismatch",
            ArtifactType::OauthRar,
            RAR_DETAILS,
            false,
        ),
    ]
}

fn artifact_fixture(case: &ArtifactCase) -> Fixture {
    // The binding always commits to the true credential's thumbprint; the
    // negative presents a DIFFERENT credential at verify time.
    let binding = ArtifactBinding::opaque_digest(case.artifact_type, case.credential);
    let mut presented = case.credential.to_vec();
    if !case.presents_true_credential {
        presented.extend_from_slice(b"-tampered");
    }
    let expected = if case.presents_true_credential {
        "verify_ok"
    } else {
        "mcp-re.artifact_binding_failed"
    };
    Fixture {
        artifact_check: Some(ArtifactCheck {
            binding: serde_json::to_value(&binding).expect("binding serializes"),
            credential_b64: credential_b64(&presented),
        }),
        ..Vector {
            name: case.name,
            kind: Kind::Artifact,
            expected,
        }
        .blank()
    }
}

/// h09–h14: the binding carries only a digest; the credential surface is committed
/// alongside ONLY so the fixture is self-contained. Each type has a positive
/// (matching thumbprint) and a negative (a different credential → the
/// artifact_binding_failed code).
pub(super) fn artifact_fixtures() -> Vec<Fixture> {
    artifact_cases().iter().map(artifact_fixture).collect()
}

/// h15–h17: three standards-derived handles over the mandated inputs. Positive binds
/// its inputs; negatives splice the previous-request base and tamper the opaque
/// requestState — both continuation_binding_failed.
pub(super) fn continuation_fixtures() -> Vec<Fixture> {
    let prev_base: &[u8] = b"previous-request-signature-base-bytes";
    let irr_base: &[u8] = b"input-required-response-signature-base-bytes";
    let req_state: &[u8] = b"opaque-request-state-blob";
    let continuation = HttpContinuation::build(prev_base, irr_base, req_state);
    let continuation_value = serde_json::to_value(&continuation).expect("continuation serializes");

    // Each vector re-presents the three mandated inputs, one of them replaced.
    let presenting = |name: &str, expected: &str, previous: &[u8], state: &[u8]| Fixture {
        continuation_check: Some(ContinuationCheck {
            continuation: continuation_value.clone(),
            previous_request_base_b64: credential_b64(previous),
            input_required_response_base_b64: credential_b64(irr_base),
            request_state_b64: credential_b64(state),
        }),
        ..Vector {
            name,
            kind: Kind::Continuation,
            expected,
        }
        .blank()
    };
    vec![
        // h15 — valid: the client re-presents the exact mandated inputs.
        presenting("h15_continuation_valid", "verify_ok", prev_base, req_state),
        // h16 — splice: a different previous-request base is presented.
        presenting(
            "h16_continuation_splice",
            "mcp-re.continuation_binding_failed",
            b"a-different-previous-request-base",
            req_state,
        ),
        // h17 — tampered opaque requestState.
        presenting(
            "h17_continuation_request_state_tamper",
            "mcp-re.continuation_binding_failed",
            prev_base,
            b"opaque-request-state-blob-TAMPERED",
        ),
    ]
}
