// SPDX-License-Identifier: Apache-2.0
//! Everything an audit of the SHIPPED `mcp-re-auditor` binary needs: the documents it is
//! given, the child process, and the archive it audits.
//!
//! These lanes exercise the shipped path — a child process, real files, an exit status —
//! because a composition root proved only in-process is a composition root nobody can run.

use super::fixtures::{
    client_key, root_key, ts_key, Scratch, AUD, CLIENT_KEY_ID, EPOCH, ISSUER_KID, ISSUER_SEED, NOW,
    ROOT_KID, TARGET, TS_KID,
};
use super::server::{build_server, serve_one};
use mcp_re_proxy::transparency::auditor::AttestationDocument;
use mcp_re_test_paths::unique_test_nonce;
use std::sync::Arc;

/// The audit profile matching the posture `build_server` serves under.
pub(super) fn audit_profile_json() -> serde_json::Value {
    serde_json::json!({
        "schema": "mcp-re-audit-profile/v1",
        "trust_domain": "mcp.example.com",
        "expected_audience": {
            "audience_id": AUD,
            "target_uri": TARGET,
            "route": "a",
        },
        "delegation": {
            "verifier_audiences": [AUD],
            "expected_audience_hash": AUD,
            "accepted_epochs": [EPOCH],
            "max_clock_skew_secs": 60,
        },
        "response_anchor": {
            "subject": "did:example:server",
            "key_id": ROOT_KID,
            "public_key": root_key().public_key().to_b64url(),
        },
        "transparency_service_keys": [ts_key_lifecycle(TS_KID)],
    })
}

/// A transparency-service key lifecycle admitting the auditor's real clock: valid since
/// before this suite was written, with no expiry and no revocation.
pub(super) fn ts_key_lifecycle(kid: &str) -> serde_json::Value {
    serde_json::json!({ "kid": kid, "valid_from": 1_600_000_000 })
}

/// A legal transparency-service trust pin. Its key is never used in this half — the
/// auditor loads it as a precondition and names the service in the artifact — so the pin
/// is the prototype log's key, which is the one a receipt from it would verify under.
pub(super) fn service_pin_json() -> serde_json::Value {
    serde_json::json!({
        "schema": "mcp-re-scitt-service-trust-pin/v1",
        "service_identifier": "prototype-log",
        "discovery_method": "well-known-scitt-keys",
        "discovery_uri": "https://ts.example.test/.well-known/scitt-keys",
        "fetched_at": "2026-09-08T00:00:00Z",
        "kid": TS_KID,
        "algorithm": "EdDSA",
        "public_key": { "x": ts_key().public_key().to_b64url() },
        "public_key_thumbprint": "unused-by-this-lane",
        "discovery_document_digest": "unused-by-this-lane",
        "leaf_profile": "statement-bytes",
        "position_profile": "bound",
    })
}

/// How an audit run asks the auditor to register its attestation with a service.
pub(super) struct Registration<'a> {
    pub(super) base: &'a str,
    /// The `--registration-protocol` token, when the operator names one.
    pub(super) protocol: Option<&'a str>,
    pub(super) timeout_secs: u32,
    /// Only a polling contract takes a poll interval; naming one for capsule-anchor is
    /// refused.
    pub(super) poll_interval_secs: Option<u32>,
}

impl Registration<'_> {
    fn args(&self) -> Vec<String> {
        let mut args = vec!["--register-to".to_owned(), self.base.to_owned()];
        if let Some(protocol) = self.protocol {
            args.extend(["--registration-protocol".to_owned(), protocol.to_owned()]);
        }
        args.extend([
            "--registration-timeout-secs".to_owned(),
            self.timeout_secs.to_string(),
        ]);
        if let Some(poll) = self.poll_interval_secs {
            args.extend([
                "--registration-poll-interval-secs".to_owned(),
                poll.to_string(),
            ]);
        }
        args
    }
}

/// The documents one audit run is asserted by, written into a scratch directory.
pub(super) struct AuditFixtures {
    profile: std::path::PathBuf,
    trust: std::path::PathBuf,
    pin: std::path::PathBuf,
    seed: std::path::PathBuf,
    pub(super) out: std::path::PathBuf,
}

impl AuditFixtures {
    pub(super) fn write(
        scratch: &Scratch,
        profile: serde_json::Value,
        pin: serde_json::Value,
    ) -> Self {
        let trust_json = serde_json::json!([{
            "signer": "did:example:client",
            "key_id": CLIENT_KEY_ID,
            "public_key": client_key().public_key().to_b64url(),
        }]);
        let fixtures = AuditFixtures {
            profile: scratch.join("audit-profile.json"),
            trust: scratch.join("trust.json"),
            pin: scratch.join("service-pin.json"),
            seed: scratch.join("issuer.seed"),
            out: scratch.join("attestation.json"),
        };
        let write_json = |path: &std::path::Path, value: &serde_json::Value, what: &str| {
            std::fs::write(path, serde_json::to_vec(value).expect("json"))
                .unwrap_or_else(|e| panic!("write {what}: {e}"));
        };
        write_json(&fixtures.profile, &profile, "profile");
        write_json(&fixtures.trust, &trust_json, "trust");
        write_json(&fixtures.pin, &pin, "pin");
        std::fs::write(&fixtures.seed, mcp_re_core::b64url_encode(&ISSUER_SEED))
            .expect("write seed");
        fixtures
    }

    pub(super) fn args(&self, evidence: &std::path::Path, hops: &[String]) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "--retained-evidence-dir".into(),
            evidence.display().to_string(),
            "--audit-profile".into(),
            self.profile.display().to_string(),
            "--trust-document".into(),
            self.trust.display().to_string(),
            "--service-trust-pin".into(),
            self.pin.display().to_string(),
            "--issuer-kid".into(),
            ISSUER_KID.into(),
            "--issuer-key-seed".into(),
            self.seed.display().to_string(),
            "--out".into(),
            self.out.display().to_string(),
            "--at".into(),
            NOW.to_string(),
        ];
        for hop in hops {
            args.push("--hop".into());
            args.push(hop.clone());
        }
        args
    }

    /// `args`, followed by the registration `registration` asks for.
    pub(super) fn args_registering(
        &self,
        evidence: &std::path::Path,
        hops: &[String],
        registration: &Registration<'_>,
    ) -> Vec<String> {
        let mut args = self.args(evidence, hops);
        args.extend(registration.args());
        args
    }

    /// The attestation the run wrote, parsed.
    pub(super) fn artifact(&self, why: &str) -> AttestationDocument {
        AttestationDocument::parse(&std::fs::read(&self.out).expect(why))
            .expect("the artifact parses")
    }
}

/// Run the shipped auditor as a child process.
pub(super) fn run_auditor(args: &[String]) -> std::process::Output {
    let binary = mcp_re_test_paths::resolve_runfile("MCP_RE_AUDITOR_CLI");
    std::process::Command::new(&binary)
        .args(args)
        .output()
        .expect("the auditor binary runs")
}

/// A served call's archive on disk and the retained hop's digest token, ready for the
/// child process to audit.
///
/// The retention handle owns a writer thread and the child process opens the same
/// directory, so the handle is dropped here and the audit sees what is on disk.
pub(super) fn archive_to_audit(name: &str) -> (Scratch, String) {
    let scratch = Scratch::new(name);
    let retention = scratch.retention();
    let proxy = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&proxy, &unique_test_nonce()), 200);
    drop(retention);

    let token = scratch
        .retained_names()
        .into_iter()
        .next()
        .expect("one retained object");
    (scratch, token)
}
