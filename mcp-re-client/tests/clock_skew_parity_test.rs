// SPDX-License-Identifier: Apache-2.0
//! The sidecar and the SDKs reach one verdict on a configured clock skew.
//!
//! The sidecar reads the tolerance from its configuration document; the SDKs hand it to the
//! binding core with each verification call. Both turn it into a
//! [`mcp_re_core::MaxClockSkew`], so a value one second past the bound is refused by both
//! and the bound itself is accepted by both. A clamp on either side would show here as one
//! side accepting what the other refuses.

use mcp_re_binding_core::BindingError;
use mcp_re_binding_core::PinnedIssuer;
use mcp_re_binding_core::VerifyArgs;
use mcp_re_binding_core::MAX_CLOCK_SKEW_BOUND_SECS;
use mcp_re_client::config::ValidatedClientConfig;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_core::MaxClockSkew;
use mcp_re_core::SigningKey;

fn sidecar_document(skew: i64) -> String {
    format!(
        r#"{{
  "local": {{ "bind": "127.0.0.1:8640" }},
  "identity": {{ "key_id": "c1", "signing_key_seed_path": "/dev/null" }},
  "remote": {{
    "addr": "10.0.0.5:8600",
    "expected_server_name": "proxy.internal",
    "client_cert_path": "/dev/null",
    "client_key_path": "/dev/null",
    "server_ca_path": "/dev/null"
  }},
  "trust": {{
    "manifest_path": "/dev/null",
    "profile": "mcp-re-http-v1",
    "org_keys": [{{ "kid": "org-1", "public_key": "AAAA" }}],
    "floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }}
  }},
  "delegation": {{
    "verifier_audiences": ["v1"],
    "expected_audience_hash": "v1",
    "accepted_epochs": ["e1"],
    "max_clock_skew": {skew}
  }},
  "routes": [{{
    "route_id": "r1",
    "target_uri": "https://mcp.example.com/mcp",
    "audience": {{ "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" }},
    "extra_headers": [{{ "name": "Authorization", "value": "Bearer tok" }}],
    "artifact_bindings": [{{ "artifact_type": "oauth-dpop", "source": {{ "kind": "header", "name": "Authorization" }} }}]
  }}]
}}"#
    )
}

/// Whether the sidecar starts on a configured skew of `skew` seconds.
fn sidecar_accepts(skew: i64) -> bool {
    ValidatedClientConfig::from_json(sidecar_document(skew).as_bytes()).is_ok()
}

/// Whether an SDK verification call gets past the skew under a skew of `skew` seconds.
///
/// The response carries no signature, so a call that admits the skew ends in the profile's
/// wire verdict on the evidence; only the skew is refused before any evidence is read, and
/// that refusal is the binding's local one.
fn sdk_accepts(skew: i64) -> bool {
    let args = VerifyArgs {
        response: HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        },
        request: HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        },
        issuer: PinnedIssuer {
            key_id: "root-1".into(),
            pubkey_b64url: SigningKey::from_seed_bytes(&[7u8; 32])
                .public_key()
                .to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server-1".into(),
            retired_until: None,
        },
        verifier_audiences: vec!["v1".into()],
        expected_audience_hash: "v1".into(),
        accepted_epochs: vec!["e1".into()],
        max_clock_skew: skew,
        revoked_identifiers: Vec::new(),
        now: 1_000,
    };
    match mcp_re_binding_core::verify_response(args) {
        Err(BindingError::Local(reason)) => {
            assert!(reason.contains("max_clock_skew"), "skew {skew}: {reason}");
            false
        }
        Err(BindingError::Wire(_)) => true,
        Ok(_) => panic!("skew {skew}: an unsigned response was accepted"),
        Err(other) => panic!("skew {skew}: unexpected refusal {other:?}"),
    }
}

#[test]
fn the_sidecar_and_the_sdk_refuse_a_301_second_skew_alike() {
    let past = MaxClockSkew::BOUND_SECS + 1;
    assert_eq!(past, 301, "the bound this test is named for");
    assert!(!sidecar_accepts(past), "the sidecar refuses {past}");
    assert!(!sdk_accepts(past), "the SDK refuses {past}");
}

#[test]
fn the_sidecar_and_the_sdk_accept_the_bound_and_refuse_a_negative_skew_alike() {
    for skew in [0, 60, MaxClockSkew::BOUND_SECS, -1, i64::MAX] {
        assert_eq!(
            sidecar_accepts(skew),
            sdk_accepts(skew),
            "skew {skew}: one verdict on both sides"
        );
    }
    assert!(sidecar_accepts(MaxClockSkew::BOUND_SECS));
    assert_eq!(MAX_CLOCK_SKEW_BOUND_SECS, MaxClockSkew::BOUND_SECS);
}
