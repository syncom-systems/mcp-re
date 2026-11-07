//! The TLS transport-identity authority (MCPS-025, ADR-MCPS-014).
//!
//! What a client certificate must satisfy to be served, and what verified identity it
//! carries. The proxy terminates TLS with `rustls` (the `ring` provider), requires and
//! verifies a client certificate against a configured client-CA, and extracts the identity
//! from the leaf (first URI SAN → DNS SAN → CN). The extracted identity is handed to the
//! request handler, where the transport-binding policy (MCPS-026) ties it to the request
//! `signer`.
//!
//! Every per-request decision here takes its input as an ARGUMENT and never a connection:
//! the unmigrated rejection guards take the peer chain leaf-first
//! (`cert_lifetime_rejection_for_chain`, `ocsp_rejection_for_chain`), and
//! `resolve_authenticated_identity` takes the mechanism's acceptance — a semantic product,
//! not a representation. `routing_header_rejection` and `assertion_header` read headers. Both
//! serving shapes therefore reach the same verdict from the same input — the async fleet
//! captures the chain at handshake because `hyper` owns the stream thereafter, and
//! [`crate::blocking_mtls_harness`] reads it from the live `ServerConnection` it holds.
//! Whoever holds the connection is not part of the decision.
//!
//! # What this module does NOT own
//!
//! The blocking mTLS + HTTP/1.1 harness (ADR-MCPRE-061 §2 class 4, MCPRE-138). Accepting a
//! socket, framing a request and writing a reply is a capability that merely uses TLS; it
//! lives in [`crate::blocking_mtls_harness`]. Listener lifetime — anchors, the epoch they
//! digest to, the session store and the signing budget — belongs to
//! [`crate::tls_listener_state`] (MCPRE-137, ADR-MCPRE-062).

/// The trusted-ingress Tier-3 (ADR-MCPS-023, issue #71) assertion header. A single
/// HTTP header carrying the LB-signed, request-bound ingress assertion (the
/// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>` wire form).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup. The serve loop fails
/// closed on a DUPLICATED header (via [`RequestHeaders::count`]) before the value
/// is ever read — a duplicate signals a downstream injection attempt.
pub const MCP_INGRESS_ASSERTION_HEADER: &str = "mcp-ingress-assertion";

mod delegated;
#[cfg(feature = "fault_accept_any_client")]
pub(crate) mod fault_accept_any;
mod options;
mod peer;
mod request_guard;

pub(crate) use delegated::validated_delegated_resolver;
pub use options::{ServerOptions, TlsError};
pub(crate) use peer::served_channel_peer;
#[cfg(feature = "online_ocsp")]
pub(crate) use request_guard::ocsp_rejection_for_chain;
pub(crate) use request_guard::{assertion_header, routing_header_rejection};
