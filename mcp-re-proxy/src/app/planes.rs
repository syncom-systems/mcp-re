//! The stages that install the runtime's trust and signing planes and build the pieces the
//! serving proxy is made from: the replay tier and the inner pool. The transport plane is
//! [`super::transport`].
//!
//! Each stage hands its plane to the [`MaterializingRuntime`](crate::materializing_runtime::MaterializingRuntime)
//! the moment it exists, so a failure at any `?` reclaims what is already running through the
//! runtime's own ordering. The stages are called from [`super::run_validated`] in the order
//! the startup transcript reports them; moving a stage across another moves a posture line
//! across the trust/replay boundary.

use std::sync::Arc;

use mcp_re_http_profile::AudienceTuple;

use crate::capability_materialization::MaterializedSigningRoles;
use crate::clock::StartupReading;
use crate::http_inner::HttpInnerPool;
use crate::http_profile_dispatch::ReplayAdmission;
use crate::key_source::ResponseSigner;

use super::boot::Startup;

/// What the serving proxy resolves a signer through, and the audience it answers for.
pub(super) struct ServingSeam {
    pub(super) resolve_actor: crate::ActorResolver,
    pub(super) expected_audience: AudienceTuple,
}

/// Trust (ADR-MCPRE-056 §8). The plane owns the store, the freshness flag and the workers
/// that refresh them; what comes back is two narrow live handles.
///
/// Response-slot signing custody (ADR-MCPRE-052, MCPRE-122): delegated signing is the ONLY
/// response mode. The ROOT key is the credential issuer only; the resolver answers the
/// Response slot from the ROOT public key (by its issuer kid) and no directly-held server
/// key exists. The root key source is only borrowed here, for its public key — it moves
/// into the signing plane later.
pub(super) fn install_trust(
    start: &mut Startup<'_>,
    roots: &MaterializedSigningRoles,
) -> Result<ServingSeam, String> {
    let config = start.config;
    let values = config.config();
    let trust = crate::trust_plane::TrustPlane::materialize(
        &start.plans.trust,
        Arc::clone(&start.shutdown),
    )?;
    start.building.install_trust(trust)?;
    let resolver = start.building.trust()?.resolver();
    let response_pub = roots.response_public_key().map_err(|e| e.to_string())?;
    // The identity is derived once by the `ServerIdentity` owner and handed over whole: the
    // resolver reads the server actor, its keyid and the trust domain through the owner's
    // projections.
    let resolve_actor = super::build_actor_resolver(
        start.building.trust()?.signers(),
        Arc::clone(&resolver),
        config.state().server_identity().clone(),
        response_pub,
    );
    let expected_audience = AudienceTuple {
        audience_id: values.audience.clone(),
        target_uri: config.state().request_target().as_str().to_owned(),
        route: values.route.clone(),
    };
    Ok(ServingSeam {
        resolve_actor,
        expected_audience,
    })
}

/// ADR-MCPRE-051 §4: the AUTHORITATIVE async replay tier. The atomic insert-if-absent is
/// AWAITED on the per-core request path without blocking a runtime worker. Shared selects a
/// durable networked store — etcd (CP/linearizable) or redis (horizontally scaled) — both
/// fail closed on any store error (an outage is never a fresh nonce).
///
/// Which tier this deployment asked for is decided PURELY, from configuration alone;
/// `replay_plane` only establishes it. Every refusal the plan can raise is a statement about
/// the config; every refusal materialization raises is a statement about the build or the
/// environment.
///
/// The redis store's reconnect machinery binds to the control runtime it is CREATED in, so
/// that runtime must outlive every USE of the tier — discharged by draining the fleet before
/// anything is reclaimed, not by drop order. See `replay_plane`.
pub(super) fn materialize_replay(start: &mut Startup<'_>) -> Result<ReplayAdmission, String> {
    let replay_plan = start.config.state().replay().materialization_plan();
    Ok(crate::replay_plane::MaterializedReplay::materialize(
        &replay_plan,
        start.config.state().freshness(),
        start.building.control(),
    )?
    .into_admission())
}

/// ADR-MCPRE-051 §3: the async inner plane — a per-core pooled hyper client to the
/// stateless Streamable-HTTP inner backends. Forwarding is AWAITED, never blocking a
/// per-core runtime worker.
///
/// The backends are named where the pool that forwards to them is BUILT. Reporting them from
/// the fleet instead would mean carrying the URLs through serving purely to print them, and
/// the fleet does not forward — it accepts.
pub(super) fn inner_pool(start: &Startup<'_>) -> Result<HttpInnerPool, String> {
    let backends = &start.config.config().inner_http_urls;
    let pool = HttpInnerPool::from_url_strs(
        backends.expose().to_vec(),
        start.config.state().connection_bounds().read_timeout(),
    )?;
    eprintln!("mcp-re-proxy: HTTP inner backends {backends}");
    Ok(crate::inner_plane_bound::raised_to_fleet_ceiling(
        pool,
        start.sizing.in_flight_limit,
        start.sizing.topology,
    ))
}

/// Response-signing custody (ADR-MCPRE-056 §8; ADR-MCPRE-052). The plane owns the root
/// issuer, the delegated snapshot and the worker that maintains it; what comes back is the
/// signer alone. `roots` is MOVED in here — it was only borrowed for the channel credential
/// and the response public key.
///
/// The plane must outlive the proxy that signs with it, and it does: the proxy is a local
/// of the caller declared after [`Startup`], and `serve_fleet` returns before either drops.
pub(super) fn install_signing(
    start: &mut Startup<'_>,
    roots: MaterializedSigningRoles,
    reading: &StartupReading,
) -> Result<(), String> {
    let signing =
        crate::signing_plane::SigningPlane::materialize(&start.plans.signing, roots, reading)?;
    start.building.install_signing(signing)
}
