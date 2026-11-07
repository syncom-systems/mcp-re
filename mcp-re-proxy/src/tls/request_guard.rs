// SPDX-License-Identifier: Apache-2.0
//! The per-request transport-boundary guards: the routing-header hygiene rejection, the
//! ingress-assertion header read, the online OCSP rejection, and the one refusal they render.

use mcp_re_core::json_rpc_error_object;
use mcp_re_core::McpReError;

use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
use crate::transport::RequestHeaders;

use super::options::ServerOptions;
use super::MCP_INGRESS_ASSERTION_HEADER;

/// The historical transport-boundary refusal, bound to the request id when it can be read.
pub(super) fn transport_binding_failure(request: &[u8]) -> Vec<u8> {
    let id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    json_rpc_error_object(&McpReError::TransportBindingFailed, &id)
}

/// Extract the raw Tier-3 ingress-assertion header value to hand to the
/// post-verification LB check (issue #71), under the [`PeerIdentityProvenance::IngressAssertion`]
/// strategy ONLY. The header is fetched case-insensitively and fails CLOSED on a
/// DUPLICATE: a single header value is returned only when EXACTLY one is present.
///
/// Returns `Some(value)` for a single present header; `None` when the strategy is
/// not LB-assertion, when the header is absent (the proxy then fails closed because
/// the LB verifier requires it), or when the header is duplicated (a downstream
/// injection attempt — fail closed). The proxy's required-header guard turns the
/// resulting `None` into a closed rejection.
pub(crate) fn assertion_header<'a>(
    options: &ServerOptions,
    headers: &'a RequestHeaders,
) -> Option<&'a str> {
    match &options.peer_identity_provenance {
        PeerIdentityProvenance::IngressAssertion => {
            // Fail closed on a duplicated trust header before reading any value.
            if headers.count(MCP_INGRESS_ASSERTION_HEADER) != 1 {
                return None;
            }
            headers.first(MCP_INGRESS_ASSERTION_HEADER)
        }
        _ => None,
    }
}

/// ADR-MCPS-025 routing-header hygiene rejection — runs at the SAME per-connection
/// point as [`cert_lifetime_rejection`] (after the verified handshake, before the
/// handler). Returns `Some(error_bytes)` when a SEP-2243 routing header
/// (`Mcp-Method` / `Mcp-Name`) is duplicated or malformed, `None` when the routing
/// headers are absent or well-formed.
///
/// The proxy never routes on these headers — the signed body is authoritative —
/// so this is anti-smuggling hygiene (ADR-MCPS-025 rule 4 applying the ADR-MCPS-023
/// strict-header rules). A defect maps to `mcp-re.transport_binding_failed`, the same
/// transport-boundary token the sibling cert-lifetime / OCSP rejections use.
pub(crate) fn routing_header_rejection(
    headers: &RequestHeaders,
    request: &[u8],
) -> Option<Vec<u8>> {
    crate::transport::validate_routing_headers(headers)
        .err()
        .map(|_rejection| transport_binding_failure(request))
}

/// Online OCSP revocation rejection (#4030) — the online sibling of
/// [`cert_lifetime_rejection`], running at the SAME per-connection point (after
/// the verified handshake, before the handler). Returns `Some(error_bytes)` (a
/// `mcp-re.transport_binding_failed` JSON-RPC error bound to the request id) when
/// an OCSP checker is configured AND the verified client leaf must be rejected;
/// `None` when no checker is configured or the leaf is admitted.
///
/// Fail-closed posture (mirrors the offline CRL deny-unknown default): the leaf
/// is REJECTED unless a verified responder answered `Good` within that answer's own
/// window — `Revoked`, `Unknown`, an error (unreachable / timeout / parse), and a leaf
/// the supplied issuer did not sign all reject. The issuer is taken from the verified
/// peer chain (the cert directly after the leaf); a leaf with no chained issuer cannot
/// be checked and is rejected. The HTTP fetch carries the checker's timeout over
/// connect, send and the body read, not over name resolution (see `crate::ocsp`).
///
/// The chain is handed in leaf-first, exactly as the channel-associated credential
/// evidence carries it, so the decision does not depend on who holds the connection. The
/// policy — which responder verdicts reject, and what an unobtainable verdict means —
/// is this module's, not the caller's.
#[cfg(feature = "online_ocsp")]
pub(crate) fn ocsp_rejection_for_chain(
    chain: &[&[u8]],
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let checker = options.ocsp_checker.as_ref()?;
    let reject = || Some(transport_binding_failure(request));

    let leaf = chain.first()?;
    // The issuer is the next cert in the verified chain. Without it we cannot
    // build a CertID, so nothing can be established: reject.
    let Some(issuer) = chain.get(1) else {
        return reject();
    };

    // A transport/codec error establishes nothing either: only an answer admits.
    let admitted = checker
        .check(leaf, issuer)
        .is_ok_and(|evidence| checker.allows(evidence, std::time::SystemTime::now()));
    if admitted {
        None
    } else {
        reject()
    }
}

#[cfg(test)]
mod routing_header_tests {
    #[test]
    fn routing_header_rejection_fails_closed_on_bad_headers_only() {
        // ADR-MCPS-025 rule 4 enforcement at the transport seam. Clean/absent
        // routing headers pass; a duplicate or malformed one fails closed with
        // mcp-re.transport_binding_failed bound to the request id.
        use crate::transport::RequestHeaders;
        let req = br#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call"}"#;

        let clean = RequestHeaders::from_pairs([("Mcp-Method", "tools/call")]);
        assert!(super::routing_header_rejection(&clean, req).is_none());

        let duplicate = RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        let rejected =
            super::routing_header_rejection(&duplicate, req).expect("duplicate must reject");
        let value: serde_json::Value =
            serde_json::from_slice(&rejected).expect("json error object");
        assert_eq!(value["error"]["message"], "mcp-re.transport_binding_failed");
        assert_eq!(value["id"], "req-1");

        let malformed = RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert!(super::routing_header_rejection(&malformed, req).is_some());
    }

    #[test]
    fn the_ingress_assertion_header_is_read_only_when_exactly_one_is_present() {
        use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
        use crate::config_state::ClientCredentialWindow;
        use crate::transport::RequestHeaders;

        let window = ClientCredentialWindow::new(
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        )
        .expect("a legal credential window");
        let asserting = super::ServerOptions {
            peer_identity_provenance: PeerIdentityProvenance::IngressAssertion,
            ..super::ServerOptions::new(
                window,
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        };
        let name = super::MCP_INGRESS_ASSERTION_HEADER;
        let one = RequestHeaders::from_pairs([(name, "token-a")]);
        assert_eq!(super::assertion_header(&asserting, &one), Some("token-a"));

        let two =
            RequestHeaders::from_pairs([(name, "token-a"), (&name.to_uppercase(), "token-b")]);
        assert_eq!(super::assertion_header(&asserting, &two), None);

        let none = RequestHeaders::from_pairs([("x-other", "v")]);
        assert_eq!(super::assertion_header(&asserting, &none), None);

        let channel = super::ServerOptions {
            peer_identity_provenance: PeerIdentityProvenance::ChannelCredential,
            ..super::ServerOptions::new(
                window,
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        };
        assert_eq!(super::assertion_header(&channel, &one), None);
    }
}
