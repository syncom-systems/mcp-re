// SPDX-License-Identifier: Apache-2.0
//! `http_profile_client` — drives the `http_profile_proxy` front to prove the
//! ADR-MCPRE-050 HTTP-profile round trip end-to-end against a real FastMCP
//! Streamable-HTTP backend.
//!
//! It exercises two legs with ONE signed request:
//!   1. HAPPY PATH: sign an RFC 9421 request (`sign_request_full`), POST it, and
//!      `verify_response` the reply — proving the response is server-signed AND
//!      bound to THIS request (`;req`). The FastMCP tool result is printed from the
//!      verified body.
//!   2. REPLAY: POST the SAME signed bytes again. The proxy fails closed and
//!      returns a DELEGATED-signed rejection; the same delegated verifier proves it
//!      authentic and bound, and the frozen wire code (`mcp-re.replay_detected`) is read
//!      from the trusted body.
//!
//! Run (target from config/ports.toml via the launcher, never a literal):
//!   HPP_TARGET=http://127.0.0.1:8601/mcp \
//!   bazel run //mcp-re-proxy:http_profile_client

use mcp_re_http_profile::DelegationExpectations;

// Shared demo material; each example uses a different subset, so allow dead code.
#[allow(dead_code)]
#[path = "hpp_common/mod.rs"]
mod hpp_common;

#[path = "http_profile_client/body.rs"]
mod body;
#[path = "http_profile_client/legs.rs"]
mod legs;
#[path = "http_profile_client/request.rs"]
mod request;
#[path = "http_profile_client/wire.rs"]
mod wire;

use legs::Verification;

/// The two addresses the legs are POSTed to. Both sign over the SAME canonical
/// @target-uri (HPP_TARGET) — the logical service URI a load balancer fronts —
/// so ONE signed request is valid at ANY replica. HPP_POST_A/B point the two
/// legs at distinct replica addresses to prove CROSS-replica replay detection;
/// unset, both default to the canonical target (single-replica mode).
fn leg_addresses(target: &str) -> (String, String) {
    let post_a = std::env::var("HPP_POST_A").unwrap_or_else(|_| target.to_owned());
    let post_b = std::env::var("HPP_POST_B").unwrap_or_else(|_| post_a.clone());
    (post_a, post_b)
}

fn main() {
    let target = hpp_common::target();
    let (post_a, post_b) = leg_addresses(&target);
    let agent = wire::agent();
    let now = hpp_common::now_unix();
    let resolver = hpp_common::resolver();
    // ADR-MCPRE-052: the client enrols ONLY the root; the credential the response carries
    // is what authorizes the delegated key. A directly root-signed response is rejected
    // (`delegation_credential_missing`) — delegation is required, not preferred.
    let verifier_audiences = [hpp_common::AUDIENCE_ID];
    let accepted_epochs = [hpp_common::EPOCH];
    let expect = DelegationExpectations {
        verifier_audiences: &verifier_audiences,
        expected_audience_hash: hpp_common::AUD_SCOPE,
        accepted_epochs: &accepted_epochs,
        max_clock_skew: mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
    };

    let nonce = format!("nonce-{now}");
    let request = request::signed_call(&target, now, &nonce);
    let verification = Verification {
        resolver: &resolver,
        request: &request,
        expect: &expect,
    };

    // --- Leg 1: happy path -------------------------------------------------
    eprintln!("leg 1  POST {post_a}  (nonce={nonce})");
    verification.accept_happy_path(&wire::post(&agent, &post_a, &request));

    // --- Leg 2: replay (same signed request, possibly a DIFFERENT replica) --
    let cross = if post_b == post_a {
        ""
    } else {
        "  [CROSS-REPLICA]"
    };
    eprintln!("leg 2  POST {post_b}  (SAME nonce -> replay){cross}");
    verification.reject_replay(&wire::post(&agent, &post_b, &request));

    println!("OK  HTTP-profile round trip + replay rejection both proven");
}
