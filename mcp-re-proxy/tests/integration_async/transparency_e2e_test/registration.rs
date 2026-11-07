// SPDX-License-Identifier: Apache-2.0
//! Registration, over a socket, through the shipped binary.
//!
//! Everything in `auditor` stops at the artifact. This is the last hop: a transparency
//! service on a loopback socket, the SHIPPED auditor pointed at it, and an artifact that
//! comes back carrying a receipt — which it can only do if that receipt verified offline
//! against the exact statement submitted and the pin the operator loaded.

use super::audit_run::{
    archive_to_audit, audit_profile_json, run_auditor, service_pin_json, AuditFixtures,
    Registration,
};
use super::fixtures::assert_verifies_offline_under_prototype;
use super::service::{spawn_transparency_service, ServiceMode};
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_proxy::transparency::auditor::AttestationDocument;

/// Run one audit that also registers, and return the artifact it wrote.
fn audit_and_register(name: &str, mode: ServiceMode) -> AttestationDocument {
    let (scratch, token) = archive_to_audit(name);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let (base, service) = spawn_transparency_service(mode);

    let registration = Registration {
        base: &base,
        protocol: Some(mode.protocol()),
        timeout_secs: 20,
        poll_interval_secs: (mode.protocol() == "scrapi-11").then_some(1),
    };
    let output =
        run_auditor(&fixtures.args_registering(&scratch.join("evidence"), &[token], &registration));
    assert!(
        output.status.success(),
        "the registration did not succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let _ = service.join();

    let artifact = fixtures.artifact("the artifact was written");
    let protocol = artifact
        .claimed_registration()
        .map(|r| r.protocol())
        .expect("a registered artifact claims its registration protocol");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(protocol),
        "the summary must name the protocol the artifact records ({protocol}): {stdout}",
    );
    artifact
}

/// The receipt an artifact carries verifies offline against the statement beside it and
/// the pin the operator captured — contacting nobody.
fn assert_receipt_verifies_offline(artifact: &AttestationDocument) {
    let statement =
        SignedStatement::from_cose(artifact.signed_statement()).expect("a Signed Statement");
    let receipt_bytes = artifact
        .claimed_registration()
        .expect("a registered artifact carries a receipt")
        .receipt()
        .to_vec();
    let receipt = Receipt::from_cose(&receipt_bytes).expect("a Receipt");
    assert_verifies_offline_under_prototype(
        &statement,
        &receipt,
        "the archived receipt verifies with no service running",
    );
}

/// The binary judges the receipt's service key by the audit profile's stated lifecycle at
/// the host's clock: a receipt that verifies against the pin, under a key the profile says
/// was revoked before now, is not recorded.
#[test]
fn a_receipt_under_a_revoked_service_key_is_not_recorded() {
    let (scratch, token) = archive_to_audit("auditor-register-revoked-key");
    let mut profile = audit_profile_json();
    profile["transparency_service_keys"][0]["revoked_at"] = 1_600_000_001.into();
    let fixtures = AuditFixtures::write(&scratch, profile, service_pin_json());
    let (base, service) = spawn_transparency_service(ServiceMode::CapsuleAnchor);

    let registration = Registration {
        base: &base,
        protocol: Some("capsule-anchor"),
        timeout_secs: 20,
        poll_interval_secs: None,
    };
    let output =
        run_auditor(&fixtures.args_registering(&scratch.join("evidence"), &[token], &registration));
    let _ = service.join();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a receipt under a revoked key must not read as success"
    );
    assert!(stderr.contains("ts_key_revoked"), "{stderr}");
    let artifact = fixtures.artifact("the attestation is still written");
    assert!(
        artifact.claimed_registration().is_none(),
        "the refused receipt must not be recorded",
    );
}

/// THE C2 property, synchronously: the shipped binary registers a real attestation with a
/// service over a socket, and the artifact comes back carrying the receipt.
///
/// The receipt is then re-verified here, WITH NO NETWORK — the service thread has already
/// exited — against the previously captured pin. That is the shape the external
/// interoperability claim is earned in, run against a hermetic service.
#[test]
fn the_auditor_binary_registers_a_statement_and_keeps_a_verified_receipt() {
    let artifact = audit_and_register("auditor-register", ServiceMode::Synchronous);
    assert_receipt_verifies_offline(&artifact);
}

/// The SECOND mechanism, through the same binary: the `capsule-anchor` contract.
///
/// The hermetic service refuses to read this submission the SCRAPI way — it asserts the
/// resource and parses the JSON envelope — so a leaf that sent the other contract's request
/// fails here rather than passing on a family resemblance. What comes back is a receipt
/// inside JSON, and the artifact carries it only because it verified offline.
///
/// It also records WHICH contract answered, which is what stops the claim exceeding the
/// peer: this run is external Transparency Service interoperability, not SCRAPI.
#[test]
fn the_auditor_binary_registers_over_the_second_mechanism_and_records_which_one() {
    let artifact = audit_and_register("auditor-register-capsule", ServiceMode::CapsuleAnchor);
    assert_receipt_verifies_offline(&artifact);
    assert_eq!(
        artifact.claimed_registration().map(|r| r.protocol()),
        Some("capsule-anchor /transparency"),
        "the artifact must name the contract that answered, not merely that one did",
    );
}

/// And the SCRAPI path records its own revision, so the two are distinguishable in the
/// artifact rather than only in whoever ran the command.
#[test]
fn a_scrapi_registration_records_the_draft_revision_it_spoke() {
    let artifact = audit_and_register("auditor-register-names-scrapi", ServiceMode::Synchronous);
    assert_eq!(
        artifact.claimed_registration().map(|r| r.protocol()),
        Some("draft-ietf-scitt-scrapi-11"),
    );
}

/// The asynchronous path — `202` → `204` → `204` → `200` — through the same binary.
#[test]
fn the_auditor_binary_polls_an_asynchronous_registration_to_its_receipt() {
    let artifact = audit_and_register(
        "auditor-register-async",
        ServiceMode::Asynchronous { pending: 2 },
    );
    assert_receipt_verifies_offline(&artifact);
}

/// A registration that does not succeed does NOT cost the attestation.
///
/// The auditor writes the artifact before it submits anything, so an operator who cannot
/// reach a transparency service still holds a portable, offline-verifiable record. The
/// exit status is non-zero and the artifact is on disk with no receipt — which is the
/// honest pair of facts.
#[test]
fn a_failed_registration_leaves_the_attestation_behind() {
    let (scratch, token) = archive_to_audit("auditor-register-down");
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    // A port nothing is listening on: bind it, learn the number, drop the listener.
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr").port()
    };

    let base = format!("http://127.0.0.1:{port}");
    let registration = Registration {
        base: &base,
        protocol: None,
        timeout_secs: 2,
        poll_interval_secs: Some(1),
    };
    let output =
        run_auditor(&fixtures.args_registering(&scratch.join("evidence"), &[token], &registration));

    assert!(
        !output.status.success(),
        "a registration that did not happen must not read as success",
    );
    let artifact = fixtures.artifact("the attestation survives a failed submission");
    assert!(
        artifact.claimed_registration().is_none(),
        "no receipt was verified, so the artifact must carry none",
    );
    assert!(
        artifact.claimed_chain().is_complete(),
        "and the attestation itself is unaffected",
    );

    // The message must preserve the certainty: the statement went nowhere we can prove.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the attestation was written"),
        "an operator must be told the record survived: {stderr}",
    );
    assert!(
        stderr.contains(&fixtures.out.display().to_string()),
        "the operator must be told where the surviving attestation is: {stderr}",
    );
    assert!(
        stderr.contains("draft-ietf-scitt-scrapi-11"),
        "and which protocol revision was attempted: {stderr}",
    );
}
