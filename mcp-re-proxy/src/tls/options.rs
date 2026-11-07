// SPDX-License-Identifier: Apache-2.0
//! What the serve loop is configured with, and the errors building the TLS server
//! configuration.

use std::sync::Arc;

use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
use crate::transport::IdentityPolicy;

/// How the serve loop turns a connection into a served request: which client-cert
/// field is the authoritative identity, the resource limits, and the maximum
/// client-certificate lifetime.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// The authoritative client-certificate identity field (no implicit fallback).
    /// Used for [`PeerIdentityProvenance::ChannelCredential`].
    pub identity_policy: IdentityPolicy,
    /// Where the request's verified transport identity is taken from. Mutually
    /// exclusive by construction.
    pub peer_identity_provenance: PeerIdentityProvenance,
    /// The limits serving reads that no other owner holds: the two size ceilings and the
    /// per-core in-flight ceiling.
    pub limits: crate::deployment_request::ServedLimits,
    /// The read, write and request-deadline timeouts, the connection ceiling and the drain
    /// window, every one in force. The async serving path reads these here and never from
    /// [`Self::limits`], so it has no disabled-bound arm to take.
    pub connection_bounds: crate::config_state::ConnectionBounds,
    /// The lifetime ceiling and the connection-age bound, one owner-sealed fact. There is
    /// no options value without it, so the per-request currency check always evaluates
    /// the lifetime ceiling.
    pub client_credential_window: crate::config_state::ClientCredentialWindow,
    /// PER-REQUEST offline CRL revocation: the revoked-serial index built from the
    /// SAME CRLs the handshake verifier holds, behind an atomic swap so a reload
    /// reaches connections that are already open.
    ///
    /// rustls runs client authentication on a full handshake only, so without this a
    /// revoked peer keeps serving for as long as it holds one connection — the
    /// `--client-crl-reload-secs` rebuild reaches only NEW connections, and
    /// `max_connection_age` bounds the exposure without ending it. `None` disables
    /// the per-request check; `app.rs` installs it only when CRLs are configured, so
    /// a deployment with none is unchanged.
    pub client_revocation: Option<Arc<crate::client_revocation::SharedClientRevocation>>,
    /// ONLINE OCSP client-cert revocation (#4030), the online sibling of #3839's
    /// offline CRL posture. When `Some`, after the handshake the serve loop asks
    /// the leaf's OCSP responder whether it is revoked, BEFORE the handler, and
    /// fails closed (rejects) on `Revoked`/`Unknown`/error (see [`ocsp_rejection_for_chain`]).
    /// `None` disables the online
    /// check (the default). This field — and the entire online check — exists
    /// ONLY in a build with the `online_ocsp` feature; the default build has no
    /// such field and the hook is a compile-time no-op, so it is byte-for-byte
    /// unchanged.
    #[cfg(feature = "online_ocsp")]
    pub ocsp_checker: Option<crate::ocsp::OcspChecker>,
    /// The canonical RFC 9421 `@target-uri` this deployment binds requests to
    /// (ADR-MCPRE-050). Client and server MUST agree on it byte-for-byte; the
    /// verifier checks it against the request evidence block's audience tuple, and the
    /// serve loop checks each request's arrival path against its origin form.
    pub target: crate::config_state::RequestTarget,
}

impl ServerOptions {
    /// Options with every field at its default except the required window and target.
    ///
    /// `pub` because it replaces the public `Default` for out-of-crate embedders
    /// (`serve_once` callers): a window and a target are required, so no inhabitant leaves
    /// currency unexamined or the arrival-path check unanswerable. The composition root keeps an exhaustive literal, so an omitted
    /// revocation index or custody flag stays a compile error there.
    pub fn new(
        client_credential_window: crate::config_state::ClientCredentialWindow,
        target: crate::config_state::RequestTarget,
    ) -> Self {
        ServerOptions {
            identity_policy: IdentityPolicy::RECOMMENDED,
            peer_identity_provenance: PeerIdentityProvenance::default(),
            limits: crate::deployment_request::ServedLimits::default(),
            connection_bounds: crate::config_state::ConnectionBounds::default(),
            client_credential_window,
            client_revocation: None,
            #[cfg(feature = "online_ocsp")]
            ocsp_checker: None,
            target,
        }
    }
}

/// Errors building the TLS server configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A client-CA certificate could not be added to the trust store.
    #[error("invalid client CA certificate")]
    BadClientCa,
    /// The client-certificate verifier could not be built.
    #[error("client verifier build failed: {0}")]
    Verifier(String),
    /// The server certificate/key or protocol configuration was rejected.
    #[error("server TLS config failed: {0}")]
    Config(String),
    /// Delegated TLS (ADR-MCPS-028 §G, issue #58): the leaf certificate's
    /// `SubjectPublicKeyInfo` is not an RFC 8410 Ed25519 key (delegated TLS is
    /// Ed25519-only), OR the delegated signer's public key does not match the leaf
    /// certificate's public key. Either is a deployment error and FAILS CLOSED at
    /// config construction — no server is started.
    #[error("delegated TLS credential mismatch: {0}")]
    DelegatedKeyMismatch(CredentialKeyCorrespondenceRefusal),
}
