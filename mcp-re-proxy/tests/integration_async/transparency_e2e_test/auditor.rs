// SPDX-License-Identifier: Apache-2.0
//! What an operator runs: the SHIPPED `mcp-re-auditor` turning a retained archive into an
//! attestation, or refusing.

use super::audit_run::{
    archive_to_audit, audit_profile_json, run_auditor, service_pin_json, AuditFixtures,
};
use super::fixtures::{
    assert_verifies_offline_under_prototype, sign_with, ts_key, Scratch, TS_KID,
};
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_proxy::transparency::auditor::ChainVerdict;
use mcp_re_proxy::transparency::auditor::CorrespondenceVerdict;
use mcp_re_proxy::transparency::auditor::IncompleteAt;
use mcp_re_proxy::transparency::EvidenceRetention;

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// THE C1 property: a served call, an archive on disk, and the SHIPPED BINARY turns it
/// into an attestation whose Signed Statement registers and verifies offline.
///
/// The last step is what makes this more than "the process exited 0": the bytes the
/// artifact carries are put through a transparency log and the RFC 9942 offline
/// verification, so an artifact carrying a statement that could not be registered would
/// fail here rather than look like a success.
#[test]
fn the_auditor_binary_turns_a_served_call_into_a_verifiable_attestation() {
    let (scratch, token) = archive_to_audit("auditor-vertical");

    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let output =
        run_auditor(&fixtures.args(&scratch.join("evidence"), std::slice::from_ref(&token)));
    assert!(
        output.status.success(),
        "the auditor refused a record it should attest: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = fixtures.artifact("the artifact was written");

    assert!(
        artifact.claimed_chain().is_complete(),
        "a single terminal hop, fully verified, is a complete record: {:?}",
        artifact.claimed_chain(),
    );
    assert_eq!(
        artifact.claimed_correspondence(),
        CorrespondenceVerdict::BoundToVerifiedCall,
        "the statement is bound to the retained bytes of a verified call",
    );
    assert_eq!(
        artifact.transparency_service().service_identifier,
        "prototype-log",
        "the artifact names the service the operator's pin selected",
    );

    // The statement the artifact carries is the real thing: register it and verify the
    // receipt offline, contacting nobody.
    let statement = SignedStatement::from_cose(artifact.signed_statement())
        .expect("the artifact carries a Signed Statement");
    assert!(statement.commitment().is_complete_record());

    let mut service = PrototypeTransparencyService::new(TS_KID);
    let receipt = service
        .register(&statement, sign_with(ts_key()))
        .expect("the statement registers");
    assert_verifies_offline_under_prototype(
        &statement,
        &receipt,
        "the receipt over the binary's statement verifies offline",
    );
}

/// MCPRE-179: the SHIPPED BINARY audits an archive it has no write access to.
///
/// This is the whole point of splitting a read projection out of the retention authority.
/// Before it, `EvidenceRetention::open` was the only way in and it proves the directory
/// writable BY WRITING a probe object — so an auditor could not run against a read-only
/// mount or a filesystem snapshot, which is the ordinary way an archive is handed to
/// somebody meant to audit it and not to add to it.
///
/// The directory is `0555` for the whole child run, so a probe write, a `create_dir_all`
/// on a missing root, or any staged object would fail. The audit succeeding is the
/// evidence that none of them is attempted.
#[test]
#[cfg(unix)]
fn the_auditor_binary_audits_an_archive_it_cannot_write_to() {
    let (scratch, token) = archive_to_audit("auditor-read-only");
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let evidence = scratch.join("evidence");
    set_mode(&evidence, 0o555);

    let output = run_auditor(&fixtures.args(&evidence, std::slice::from_ref(&token)));

    // Restore before asserting, so the scratch can be removed either way.
    set_mode(&evidence, 0o700);
    assert!(
        output.status.success(),
        "auditing must not require write access to the evidence it attests: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let artifact = fixtures.artifact("the artifact was written");
    assert!(artifact.claimed_chain().is_complete());
}

/// And the SERVING constructor still refuses the same directory, at startup.
///
/// The narrowing is on the read side only. A replica that starts on a read-only volume, a
/// `0555` directory or a mismatched `fsGroup` would otherwise refuse every call it then
/// accepted, and that failure has to surface where an operator is looking.
#[test]
#[cfg(unix)]
fn the_serving_constructor_still_proves_the_archive_writable() {
    let scratch = Scratch::new("retention-writability-gate");
    let evidence = scratch.join("evidence");
    std::fs::create_dir_all(&evidence).expect("create");
    set_mode(&evidence, 0o555);

    let serving = EvidenceRetention::open(&evidence);
    let reading = mcp_re_proxy::transparency::RetainedArchive::open_read_only(&evidence);

    set_mode(&evidence, 0o700);
    assert!(
        serving.is_err(),
        "a serving replica must not start on an archive it cannot write",
    );
    assert!(reading.is_ok(), "reading needs no write authority");
}

/// A hop the archive does not hold is a REFUSAL, and nothing is written.
///
/// The alternative — reconstructing from the hops that happen to be present — would
/// produce a `Complete` label for a record with a hole in it. The absence of the output
/// file is asserted too: a run that refused after writing would leave an artifact
/// describing an audit that did not happen.
#[test]
fn a_hop_the_archive_does_not_hold_is_refused_and_writes_nothing() {
    let (scratch, token) = archive_to_audit("auditor-missing-hop");
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    let absent = mcp_re_http_profile::scitt::EvidenceDigest::of(b"a hop nobody retained")
        .as_str()
        .to_owned();
    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token, absent]));

    assert!(!output.status.success(), "a missing hop must refuse");
    assert!(
        !fixtures.out.exists(),
        "a refused audit must leave no artifact behind",
    );
}

/// An illegal service pin refuses the run BEFORE anything is signed.
///
/// A statement cut for a service whose pin is illegal can never be shown to have been
/// registered with that service, so producing one would produce an artifact with no
/// possible future. The pin is loaded first for exactly that reason.
#[test]
fn an_illegal_service_pin_refuses_the_audit() {
    let (scratch, token) = archive_to_audit("auditor-bad-pin");

    // An EdDSA pin carrying an EC2 `y` coordinate is a mislabelled key, and never becomes
    // a pin at all.
    let mut pin = service_pin_json();
    pin["public_key"]["y"] = ts_key().public_key().to_b64url().into();
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), pin);

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(!output.status.success(), "an illegal pin must refuse");
    assert!(!fixtures.out.exists(), "and must leave no artifact");
}

/// A profile asserting a posture the record was NOT served under yields an INCOMPLETE
/// attestation — not a refusal, and not a complete one.
///
/// This is the §9 seam reaching the shipped binary. The auditor asserts an audience the
/// call never had; every hop fails the full-profile comparison; and what comes out is a
/// portable statement that says so, naming the hop and the frozen wire code. An auditor
/// that refused here would leave the interesting record with no evidence, and one that
/// labelled it complete would launder it.
#[test]
fn an_audit_posture_the_call_was_not_served_under_attests_an_incomplete_record() {
    let (scratch, token) = archive_to_audit("auditor-wrong-posture");

    let mut profile = audit_profile_json();
    profile["expected_audience"]["audience_id"] = "some-other-verifier".into();
    let fixtures = AuditFixtures::write(&scratch, profile, service_pin_json());

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(
        output.status.success(),
        "an incomplete record is attested, not refused: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = fixtures.artifact("an artifact was still written");

    let ChainVerdict::Incomplete { hop, reason, .. } = artifact.claimed_chain() else {
        panic!("a record served under another audience is not complete");
    };
    assert_eq!(*hop, 0, "the first hop is where it broke");
    assert_eq!(*reason, IncompleteAt::RequestUnverifiable);
    assert_eq!(
        artifact.claimed_correspondence(),
        CorrespondenceVerdict::BoundToSubmissionOnly,
        "nothing verified, so the statement binds the SUBMISSION and says only that",
    );

    let statement =
        SignedStatement::from_cose(artifact.signed_statement()).expect("still a Signed Statement");
    assert!(
        !statement.commitment().is_complete_record(),
        "and the signed record can never read as whole",
    );
}

/// An archive object that was replaced on disk is refused, not reconstructed from.
///
/// The store is content-addressed, so the tamper is detectable by the name alone — and
/// this is the lane that proves the auditor consults that property rather than trusting
/// the directory it was pointed at.
#[test]
fn a_tampered_archive_object_is_refused() {
    let (scratch, token) = archive_to_audit("auditor-tampered");
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    let object = scratch.join("evidence").join(&token);
    let mut bytes = std::fs::read(&object).expect("read the retained object");
    bytes.push(b' ');
    std::fs::write(&object, &bytes).expect("replace the retained object");

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(
        !output.status.success(),
        "bytes that do not hash to the digest they are stored under must refuse",
    );
    assert!(!fixtures.out.exists(), "and must leave no artifact");
}
