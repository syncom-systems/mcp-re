// SPDX-License-Identifier: Apache-2.0
//! The LIVE external lane, deliberately off the merge path.
//!
//! Everything in `registration` is hermetic. This one needs a third party's service and a
//! network, so it cannot be a merge gate: a red build would then mean "somebody else's
//! server is down". It is opt-in, and it is the ONLY thing in this repository that earns
//! the external interoperability sentence — the frozen corpus in
//! `mcp-re-conformance/tests/vectors/scitt/interop/capsule-anchor-live/` is what one of its
//! runs produced.
//!
//! The reason it is a test rather than a script: the property is about the SHIPPED BINARY
//! end to end — serve a call, retain it, attest it, register it, verify the receipt — and a
//! script would re-implement the half that matters.

use super::audit_run::{
    archive_to_audit, audit_profile_json, run_auditor, ts_key_lifecycle, AuditFixtures,
    Registration,
};
use super::fixtures::{issuer_key, ISSUER_KID};
use mcp_re_http_profile::scitt::CoseVerificationKey;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;

/// The live service's base URL and pin path, when an operator asked for the live lane.
fn live_transparency_service() -> Option<(String, std::path::PathBuf)> {
    let url = std::env::var("MCP_RE_LIVE_TRANSPARENCY_SERVICE").ok()?;
    let pin = std::env::var("MCP_RE_LIVE_TRANSPARENCY_PIN").expect(
        "MCP_RE_LIVE_TRANSPARENCY_SERVICE without MCP_RE_LIVE_TRANSPARENCY_PIN: a \
                 receipt is not accepted until it verifies against a pin cut out of band, \
                 so the live lane cannot run without one",
    );
    Some((url, pin.into()))
}

/// The receipt the artifact carries is present ONLY because the auditor verified it
/// offline against the pin; that is the whole meaning of the field. Re-derived here so the
/// lane states the property rather than trusting the process that just ran.
fn assert_live_receipt_verifies_against(
    artifact: &mcp_re_proxy::transparency::auditor::AttestationDocument,
    live_pin: serde_json::Value,
) {
    let receipt = artifact
        .claimed_registration()
        .expect("a live registration must carry a receipt")
        .receipt()
        .to_vec();
    let statement =
        SignedStatement::from_cose(artifact.signed_statement()).expect("a Signed Statement");
    let pin: ScittServiceTrustPin = serde_json::from_value(live_pin).expect("the pin deserializes");
    mcp_re_http_profile::scitt::verify_receipt_offline(
        &statement,
        &mcp_re_http_profile::scitt::Receipt::from_cose(&receipt).expect("a Receipt"),
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| pin.resolve(kid),
    )
    .expect("the live service's receipt verifies offline against the pre-cut pin");
}

/// THE external-interoperability property: the shipped auditor registers with a
/// Transparency Service SOMEBODY ELSE OPERATES, and keeps a receipt that verified offline
/// against a pin cut before the run.
///
/// Opt-in, via `MCP_RE_LIVE_TRANSPARENCY_SERVICE` and `MCP_RE_LIVE_TRANSPARENCY_PIN`. With
/// them unset this lane MEASURES NOTHING and says so on stdout rather than passing quietly
/// — a green that measured nothing is worse than a red one. With them set nothing about it
/// is tolerant: a service that will not answer, or a receipt that will not verify, fails.
///
/// What a passing run earns is *external Transparency Service interoperability* and exactly
/// that. Whether it also earns *SCRAPI interoperability* depends on which peer answered, and
/// the artifact records which — this lane asserts the artifact says so rather than assuming.
#[test]
fn the_auditor_binary_registers_with_a_live_external_service() {
    let Some((base, pin_path)) = live_transparency_service() else {
        println!(
            "SKIPPED and therefore MEASURED NOTHING: set \
             MCP_RE_LIVE_TRANSPARENCY_SERVICE=<base url> and \
             MCP_RE_LIVE_TRANSPARENCY_PIN=<pin path> to run the live external lane. \
             Do not read this lane's absence as evidence of interoperability."
        );
        return;
    };
    // Named, never guessed — the same rule the auditor itself applies. The default is the
    // contract the one operated peer this project has reached actually speaks; pointing the
    // lane at a SCRAPI peer is a matter of setting this and the pin.
    let protocol = std::env::var("MCP_RE_LIVE_TRANSPARENCY_PROTOCOL")
        .unwrap_or_else(|_| "capsule-anchor".to_owned());

    let (scratch, token) = archive_to_audit("auditor-live");
    let live_pin: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pin_path).expect("the live pin is readable"))
            .expect("the live pin parses");
    let mut profile = audit_profile_json();
    profile["transparency_service_keys"] = serde_json::json!([ts_key_lifecycle(
        live_pin["kid"]
            .as_str()
            .expect("the live pin names its kid")
    )]);
    let fixtures = AuditFixtures::write(&scratch, profile, live_pin.clone());

    let registration = Registration {
        base: &base,
        protocol: Some(&protocol),
        timeout_secs: 120,
        poll_interval_secs: Some(2),
    };
    let output =
        run_auditor(&fixtures.args_registering(&scratch.join("evidence"), &[token], &registration));
    assert!(
        output.status.success(),
        "the live registration with {base} did not succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = fixtures.artifact("the artifact was written");
    assert_live_receipt_verifies_against(&artifact, live_pin);

    // The claim may not exceed the peer, so the artifact has to name it.
    let recorded = artifact
        .claimed_registration()
        .map(|r| r.protocol())
        .expect("a registered artifact names the contract that answered");
    println!(
        "LIVE EXTERNAL RUN: {base} answered over {recorded}; receipt verified offline \
         against {}. This earns external Transparency Service interoperability; it earns \
         SCRAPI interoperability only if {recorded} is a SCRAPI revision.",
        pin_path.display(),
    );
    assert!(
        !recorded.is_empty(),
        "a registered artifact must name a contract",
    );
}
