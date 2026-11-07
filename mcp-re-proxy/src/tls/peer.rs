// SPDX-License-Identifier: Apache-2.0
//! The authenticated channel peer of one served request: which peer the relationship
//! authenticated as, and the deployment's own currency controls applied to it.

use crate::communication_assurance::authenticate_relationship_peer;
use crate::communication_assurance::authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::credential_currency::evaluation::evaluate_credential_currency;
use crate::communication_assurance::credential_currency::CredentialCurrencyOutcome;
use crate::communication_assurance::credential_currency::CredentialCurrencyPolicy;
use crate::communication_assurance::credential_currency::CredentialCurrencyRefusal;
use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
use crate::communication_assurance::AuthenticatedChannelPeer;
use crate::communication_assurance::MechanismVerifiedCredentialEvidence;

use super::options::ServerOptions;
use super::request_guard::transport_binding_failure;

/// The authenticated channel peer of this relationship, with whatever currency assurance
/// the deployment's controls established — for both direct-TLS serving paths
/// (ADR-MCPRE-064 Slice 4, issue #623).
///
/// The strategy dispatch is the only decision here. Under [`PeerIdentityProvenance::ChannelCredential`]
/// the peer comes from the ADR-MCPRE-064 authorities: the mechanism's own acceptance plus
/// the configured identity policy authenticate it, and the deployment's currency policy
/// then makes it a CURRENT peer or refuses it. Under
/// [`PeerIdentityProvenance::IngressAssertion`] there is no channel peer, unchanged.
///
/// **Nothing but the acceptance and the deployment's own policies is supplied.** There is
/// no certificate parameter, no leaf parameter, no chain and no identity — which is what
/// makes the historical route not merely unused from here but unavailable. Both serving
/// paths call THIS function, so their peers are the same fact and not two derivations that
/// currently agree.
///
/// One evaluation per request. A credential the currency controls REFUSE never becomes a
/// peer at all — the caller renders that as the transport-boundary refusal, exactly as
/// before — and a `ServerOptions` always evaluates the ceiling, so the unexamined outcome
/// remains only for an absent acceptance.
fn resolve_channel_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
    now: i64,
) -> Result<Option<AuthenticatedChannelPeer>, CredentialCurrencyRefusal> {
    let policy = currency_policy(options);
    let Some(peer) = authenticated_peer(accepted, options) else {
        // No channel peer to speak of — LB assertion, no acceptance, or a leaf carrying no
        // configured identity field. The credential's CURRENCY is still the deployment's
        // question, so it is asked here rather than skipped with the identity.
        return match evaluate_credential_currency(accepted, &policy, now) {
            CredentialCurrencyOutcome::Refused(refusal) => Err(refusal),
            CredentialCurrencyOutcome::NotEvaluated | CredentialCurrencyOutcome::Current(_) => {
                Ok(None)
            }
        };
    };
    AuthenticatedChannelPeer::resolve(peer, &policy, now).map(Some)
}

/// The peer this relationship authenticated as, before any currency question.
///
/// Private: the serving path consumes [`resolve_channel_peer`], which is the whole
/// question. Publishing this would let a caller take the identity half without the
/// currency half and pair them itself.
fn authenticated_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
) -> Option<AuthenticatedRelationshipPeerFacts> {
    match &options.peer_identity_provenance {
        PeerIdentityProvenance::ChannelCredential => {
            authenticate_relationship_peer(accepted?.clone(), options.identity_policy.into()).ok()
        }
        PeerIdentityProvenance::IngressAssertion => None,
    }
}

/// The channel peer for one served request, or the transport-boundary refusal.
///
/// A FACADE over [`resolve_channel_peer`], and THE single call both direct-TLS serving
/// paths make about their relationship. It asks the ADR-MCPRE-064 authorities once and
/// renders a currency refusal in the historical wire vocabulary; it parses no certificate,
/// compares no clock, consults no CRL and decides no identity — there is no check here to
/// delete.
///
/// It takes the ACCEPTANCE, never a chain: the facts are then about the credential this
/// relationship actually authenticated with, and there is no parameter through which
/// another peer's certificates could enter.
///
/// The wire outcome is unchanged. Every request production admitted is admitted, every one
/// it refused is refused, and a currency refusal is still `mcp-re.transport_binding_failed`
/// bound to the request id — the reason is typed, and rendering it on the wire is a
/// separate decision this migration does not take.
///
/// Online-OCSP revocation is refused at the legality boundary in every build, so no
/// validated deployment reaches this path with an OCSP checker.
pub(crate) fn served_channel_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
    request: &[u8],
    now: i64,
) -> Result<Option<AuthenticatedChannelPeer>, Vec<u8>> {
    resolve_channel_peer(accepted, options, now)
        .map_err(|_refusal| transport_binding_failure(request))
}

/// The deployment's configured currency controls, classified.
///
/// The deployment's currency controls, classified.
///
/// A TOTAL selector over the two policies a `ServerOptions` can state: the window's
/// ceiling alone, or the ceiling with revocation; `NotEvaluated` and revocation-only are
/// unconstructible from one. The revocation index is SNAPSHOTTED here, once per request,
/// so the leaf check and the issuer check cannot read two different indexes across a
/// reload.
fn currency_policy(options: &ServerOptions) -> CredentialCurrencyPolicy {
    let ceiling = options.client_credential_window.cert_lifetime();
    let index = options
        .client_revocation
        .as_ref()
        .map(|revocation| revocation.load());
    match index {
        None => CredentialCurrencyPolicy::Ceiling(ceiling),
        Some(index) => CredentialCurrencyPolicy::CeilingAndRevocation(ceiling, index),
    }
}

#[cfg(test)]
mod currency_policy_tests {
    //! ADR-MCPRE-064 Slice 3. The classification is a TOTAL selector over deployment state,
    //! and it is where the per-request index snapshot is taken.

    use std::sync::Arc;
    use std::time::Duration;

    use super::currency_policy;
    use super::ServerOptions;
    use crate::client_revocation::ClientRevocationIndex;
    use crate::client_revocation::SharedClientRevocation;
    use crate::communication_assurance::CredentialCurrencyPolicy;
    use crate::config_state::ClientCredentialWindow;

    fn shared() -> (
        Arc<SharedClientRevocation>,
        crate::client_revocation::ClientRevocationPublisher,
    ) {
        let (reader, publisher) = SharedClientRevocation::establish(ClientRevocationIndex::empty());
        (Arc::new(reader), publisher)
    }

    fn window(lifetime_secs: u64) -> ClientCredentialWindow {
        ClientCredentialWindow::new(Duration::from_secs(lifetime_secs), Duration::from_secs(300))
            .expect("a legal credential window")
    }

    #[test]
    fn every_deployment_classifies_to_exactly_one_policy() {
        // A total selector, and the reason the policy is an enum: evaluating with nothing
        // configured, or revocation without the ceiling, cannot be written. The ceiling
        // is the window's, not a constant.
        let (revocation, _publisher) = shared();

        for secs in [3600, 1800] {
            let expected = Duration::from_secs(secs);
            assert!(matches!(
                currency_policy(&ServerOptions::new(window(secs), crate::config_state::RequestTarget::new("https://localhost/").expect("an absolute target"))),
                CredentialCurrencyPolicy::Ceiling(d) if d == expected
            ));
            assert!(matches!(
                currency_policy(&ServerOptions {
                    client_revocation: Some(Arc::clone(&revocation)),
                    ..ServerOptions::new(window(secs), crate::config_state::RequestTarget::new("https://localhost/").expect("an absolute target"))
                }),
                CredentialCurrencyPolicy::CeilingAndRevocation(d, _) if d == expected
            ));
        }
    }

    #[test]
    fn currency_policy_reads_the_index_in_force_at_the_time_of_the_call() {
        // The half of the reload claim that moved here when the authority began taking the
        // index as a value. The broken implementation this catches is hoisting `load()` out
        // of the per-request decision — caching it per connection is exactly the
        // handshake-only posture the per-request check exists to replace.
        let (revocation, publisher) = shared();
        let options = ServerOptions {
            client_revocation: Some(Arc::clone(&revocation)),
            ..ServerOptions::new(
                window(3600),
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        };
        let before = currency_policy(&options);
        assert!(
            before
                .revocation()
                .is_some_and(ClientRevocationIndex::is_empty),
            "the first snapshot is the empty index that was in force"
        );

        publisher.publish(ClientRevocationIndex::empty());
        let after = currency_policy(&options);
        assert!(
            !std::ptr::eq(
                before.revocation().expect("configured"),
                after.revocation().expect("configured")
            ),
            "a second call must re-read the cell, not reuse the first snapshot"
        );
    }
}

#[cfg(test)]
mod channel_peer_resolution_tests {
    //! ADR-MCPRE-064 (#619, #621, #623) — the direct-TLS serving paths resolve their
    //! channel peer from the AUTHENTICATED peer and the deployment's own currency policy,
    //! never from certificate representation.
    //!
    //! Every control drives a real handshake. What a synthetic chain would prove about
    //! which credential a relationship authenticated with is nothing, and the property at
    //! stake here is provenance rather than parsing.

    use super::*;
    use crate::transport::IdentityPolicy;
    use std::time::Duration;

    use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
    use crate::communication_assurance::CertificateIdentitySource;

    use crate::config_state::ClientCredentialWindow;
    use rustls::HandshakeKind;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    const IDENTITY_A: &str = "spiffe://example.org/A";
    const IDENTITY_B: &str = "spiffe://example.org/B";

    fn window() -> ClientCredentialWindow {
        ClientCredentialWindow::new(Duration::from_secs(3600), Duration::from_secs(300))
            .expect("a legal credential window")
    }

    fn direct_tls(policy: IdentityPolicy) -> ServerOptions {
        ServerOptions {
            identity_policy: policy,
            peer_identity_provenance: PeerIdentityProvenance::ChannelCredential,
            ..ServerOptions::new(
                window(),
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        }
    }

    /// A real relationship whose client chain is `[leaf(uri_san), intermediate(decoy)]` —
    /// the decoy answers the same policy with a DIFFERENT identity, so a route that read
    /// any certificate other than the accepted credential's leaf returns the wrong
    /// identity rather than merely a different-looking success.
    fn accepted(uri_san: &str, decoy: &str) -> MechanismVerifiedCredentialEvidence {
        let root = make_ca("serving-root");
        let intermediate = make_intermediate(&root, "serving-intermediate", decoy);
        let server_ca = make_ca("serving-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_short_lived_uri_leaf(&intermediate, uri_san);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(
            &server_ca.der(),
            Some((vec![client_leaf, intermediate.der()], client_key)),
        );
        let conn = handshake(&client, &server);
        assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
        verified_credential(&conn).expect("an established relationship accepts")
    }

    #[test]
    fn direct_tls_resolves_the_identity_the_relationship_authenticated_as() {
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let peer = resolve_channel_peer(
            Some(&acceptance),
            &direct_tls(IdentityPolicy::UriSan),
            crate::clock::now_unix(),
        )
        .expect("the short-lived credential is current under the window")
        .expect("the accepted credential's leaf carries the configured field");

        assert_eq!(peer.identity().as_str(), IDENTITY_A);
        assert_eq!(peer.identity_source(), CertificateIdentitySource::UriSan);
    }

    #[test]
    fn an_issuer_in_the_accepted_chain_never_becomes_the_transport_identity() {
        // The failure a raw-chain route invites: two certificates in the accepted chain
        // answer the policy, and reading "some certificate the peer presented" binds the
        // deployment to the CA rather than to the workload.
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let peer = resolve_channel_peer(
            Some(&acceptance),
            &direct_tls(IdentityPolicy::UriSan),
            crate::clock::now_unix(),
        )
        .expect("the short-lived credential is current under the window")
        .expect("resolution succeeds");
        assert_ne!(peer.identity().as_str(), IDENTITY_B);
    }

    #[test]
    fn each_relationship_resolves_its_own_peers_identity() {
        // The L-5 control at the serving boundary: two live relationships, one options
        // record. A route that reached past its own acceptance would answer the same
        // identity twice.
        let first = accepted(IDENTITY_A, IDENTITY_B);
        let second = accepted(IDENTITY_B, IDENTITY_A);
        let options = direct_tls(IdentityPolicy::UriSan);

        let from_first = resolve_channel_peer(Some(&first), &options, crate::clock::now_unix())
            .expect("the short-lived credential is current under the window")
            .expect("first resolves");
        let from_second = resolve_channel_peer(Some(&second), &options, crate::clock::now_unix())
            .expect("the short-lived credential is current under the window")
            .expect("second resolves");
        assert_eq!(from_first.identity().as_str(), IDENTITY_A);
        assert_eq!(from_second.identity().as_str(), IDENTITY_B);
    }

    #[test]
    fn a_resumed_relationship_resolves_the_same_identity_as_a_full_handshake() {
        // Resumption restores the stored peer chain, so it is the same peer and must
        // resolve to the same identity — while the establishment path stays DIFFERENT,
        // which is what a consumer needing "the verifier ran in this establishment" reads.
        let peers = short_lived_peers();
        let full = verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        let resumed_conn = handshake(&peers.client, &peers.server);
        assert_eq!(
            resumed_conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "without a real resumption this control is a second full handshake"
        );
        let resumed = verified_credential(&resumed_conn).expect("accepts");
        let options = direct_tls(IdentityPolicy::DnsSan);

        let from_full = resolve_channel_peer(Some(&full), &options, crate::clock::now_unix())
            .expect("the short-lived credential is current under the window")
            .expect("a peer");
        let from_resumed = resolve_channel_peer(Some(&resumed), &options, crate::clock::now_unix())
            .expect("the short-lived credential is current under the window")
            .expect("a peer");

        assert_eq!(
            from_full.identity(),
            from_resumed.identity(),
            "a resumed relationship is the same authenticated peer"
        );
        assert_eq!(
            from_full.establishment_path(),
            EstablishmentPath::FullHandshake
        );
        assert_eq!(
            from_resumed.establishment_path(),
            EstablishmentPath::ResumedSession,
            "the resumed/full distinction survives all the way to the channel peer"
        );
        assert_ne!(from_full, from_resumed);
    }

    #[test]
    fn a_leaf_without_the_configured_field_resolves_no_identity() {
        // No-fallback, at the serving boundary. The peer's leaf carries a DNS SAN and the
        // deployment configured URI SANs: the request must reach the fail-closed core with
        // no identity rather than with a weaker field's value.
        let peers = short_lived_peers();
        let acceptance =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        assert!(
            resolve_channel_peer(
                Some(&acceptance),
                &direct_tls(IdentityPolicy::UriSan),
                crate::clock::now_unix()
            )
            .expect("the short-lived credential is current under the window")
            .is_none(),
            "a present DNS SAN is not a reason to answer under a URI-SAN policy"
        );
    }

    #[test]
    fn an_absent_acceptance_resolves_no_identity() {
        // Every serving configuration states a currency window, and an absent acceptance
        // cannot be shown current under it: no peer, and no silent pass.
        assert!(
            matches!(
                resolve_channel_peer(
                    None,
                    &direct_tls(IdentityPolicy::UriSan),
                    crate::clock::now_unix()
                ),
                Err(CredentialCurrencyRefusal::CredentialUnreadable)
            ),
            "no acceptance is no authenticated peer, refused under the configured window"
        );
    }

    #[test]
    fn an_lb_assertion_deployment_resolves_no_transport_identity() {
        // Untouched by this migration: under LB assertion the client certificate is not
        // consulted for identity, and a live accepted credential must not change that.
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let options = ServerOptions {
            identity_policy: IdentityPolicy::UriSan,
            peer_identity_provenance: PeerIdentityProvenance::IngressAssertion,
            ..ServerOptions::new(
                window(),
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        };
        assert!(
            resolve_channel_peer(Some(&acceptance), &options, crate::clock::now_unix())
                .expect("the short-lived credential is current under the window")
                .is_none()
        );
    }
}
