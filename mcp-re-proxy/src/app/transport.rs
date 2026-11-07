//! The transport stages: the serving TLS plane and the options the accept loop is served
//! with.
//!
//! The TLS plane is installed after the trust posture and before the revocation posture
//! below, so the operator reads each in the order the startup transcript fixes.

use std::sync::Arc;

use crate::capability_materialization::EstablishedChannelCredential;
use crate::config_state::ChannelBindingEffects;
use crate::materialized_runtime::FleetServing;
use crate::startup_posture::Seam;
use crate::tls_plane::CrlReference;
use crate::transport::TransportBinding;
use crate::ServerOptions;

use super::boot::Startup;

/// Transport custody (ADR-MCPRE-056 §8). The plane owns the serving TLS config, the
/// per-request revocation index and the CRL reload worker; the channel credential is MOVED
/// in so no second copy of the key material can drift from the one a reload rebuilds.
///
/// Materialized after the trust posture and before the revocation posture, so a deployment
/// with both a stale CRL and an unreadable trust file sees the trust diagnostic first.
pub(super) fn install_tls(
    start: &mut Startup<'_>,
    channel_credential: EstablishedChannelCredential,
    crl_reference: CrlReference,
) -> Result<(), String> {
    let tls = crate::tls_plane::TlsPlane::materialize(
        &start.plans.tls,
        channel_credential,
        crl_reference,
        Arc::clone(&start.shutdown),
    )?;
    start.building.install_tls(tls)?;
    state_revocation_posture(start)
}

/// ADR-MCPS-023 §A1 (MCPS-58): the operator-visible revocation posture, rendered by the
/// plane that parsed the CRLs so what an operator is told is assertable in a test rather
/// than only readable in a transcript.
///
/// MCPS-85 (ADR-MCPS-049 clause 3): under `--fleet`, the PER-TIER cross-replica
/// revocation-lag bounds are stated explicitly from real config, because the two tiers have
/// different cadences. Zero-window revocation is never claimed on either.
fn state_revocation_posture(start: &Startup<'_>) -> Result<(), String> {
    let tls = start.building.tls()?;
    for line in
        crate::tls_plane::revocation_posture_lines(&start.plans.tls, &tls.revocation_currency())
    {
        eprintln!("{line}");
    }
    if start.config.state().topology().is_fleet() {
        let trust_bound = crate::trust_plane::fleet_trust_bound(&start.plans.trust);
        let crl_bound = tls.fleet_crl_bound(&start.plans.tls);
        // r12 R12-628: THREE slots, three postures. The response-slot anchor is read once and
        // held for the process lifetime — deliberately, because it is the deployment's own
        // trust anchor and is revoked by root rotation rather than by a trust-store entry —
        // so neither the trust-epoch kill switch nor the CRL reload reaches it. An operator
        // reading two numbers and an omission cannot tell that from an oversight.
        eprintln!(
            "mcp-re-proxy: FLEET cross-replica revocation-lag bounds (ADR-MCPS-049 clause 3): \
             trust-key-status={trust_bound}; client-cert-crl={crl_bound}; \
             response-signer-anchor=restart-only (read once at startup; withdrawn by root \
             rotation, not by the trust store or a CRL); zero-window revocation NOT claimed"
        );
    }
    Ok(())
}

/// What the accept loop is served with, and the channel binding the proxy compares.
pub(super) struct Serving {
    pub(super) fleet: FleetServing,
    pub(super) binding: TransportBinding,
}

/// The serving options: the Mode-A transport binding, the certificate field the identity is
/// read from and where the connection seam reads it (all projected from the ONE state
/// `config_state::transport` recognised), the owner's resolved bounds and credential
/// window, and the OCSP checker.
///
/// ONLINE OCSP client-cert revocation (#4030) is attached to `ServerOptions` rather than to
/// the PEP, because revocation is decided during the TLS handshake.
pub(super) fn serving_options(start: &mut Startup<'_>) -> Result<Serving, String> {
    let config = start.config;
    let values = config.config();
    let ChannelBindingEffects {
        binding,
        identity_policy,
        peer_identity_provenance,
    } = config.state().channel_binding().serving_effects();
    let tls = start.building.tls()?;
    let client_revocation = tls.revocation();
    let config_snapshot = tls.snapshot();
    let (ocsp_checker, ocsp_state) = crate::serving_capabilities::online_ocsp().into_parts();
    start
        .posture
        .declare(Seam::OnlineOcspClientRevocation, ocsp_state);
    // A build without the backend still DECLARES the seam above — that is the point of
    // `Seam::ALL` not varying by `cfg` — but there is no checker type in it to carry, so
    // the artifact is uninhabited and goes nowhere.
    #[cfg(not(feature = "online_ocsp"))]
    let _ = ocsp_checker;
    let options = ServerOptions {
        identity_policy,
        peer_identity_provenance,
        limits: values
            .limits
            .served(start.sizing.in_flight_limit, start.sizing.topology.shards()),
        // The owner's resolved bounds: serving reads every timeout and limit here, not the request.
        connection_bounds: config.state().connection_bounds(),
        // The owner's sealed window; serving reads both bounds from it, not from the request.
        client_credential_window: config.state().client_credential_window(),
        client_revocation,
        #[cfg(feature = "online_ocsp")]
        ocsp_checker,
        target: config.state().request_target().clone(),
    };
    Ok(Serving {
        fleet: FleetServing {
            config_snapshot,
            serve_options: Arc::new(options),
            shutdown: Arc::clone(&start.shutdown),
        },
        binding,
    })
}
