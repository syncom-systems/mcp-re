//! The serving proxy and the optional capabilities installed on it, each one stating its
//! posture in both directions.
//!
//! Every capability is established in `serving_capabilities`, where its own rule is written
//! down, and every `into_parts` is consuming: the artifact installed here and the posture
//! declared after it come from one value, so there is no store under an OFF line and no ON
//! line over nothing. Both refusals for a capability that was SELECTED and cannot be
//! established differ only in what an omitted flag means.

use std::sync::Arc;

use crate::authorization::AuthorizationEvaluator;
use crate::http_inner::HttpInnerPool;
use crate::http_profile_dispatch::ReplayAdmission;
use crate::startup_posture::Seam;
use crate::transport::TransportBinding;
use crate::HttpProfileProxy;

use super::boot::Startup;
use super::planes::ServingSeam;

/// The response-signature validity window, in seconds.
const RESPONSE_SIGNATURE_WINDOW_SECS: i64 = 300;

/// ADR-MCPRE-070 §11: a required audit commitment is established before any plane, so a
/// provider that cannot be refuses startup with nothing yet running.
pub(super) fn establish_audit_commitment(
    start: &Startup<'_>,
    audit: crate::audit_commitment::AuditPlan,
) -> Result<crate::audit_commitment::EstablishedAudit, String> {
    crate::serving_capabilities::audit_commitment(audit, start.building.control())
}

/// ADR-MCPRE-065 §8: the authorization authority — MAY-ACT, the question neither the
/// signature nor the channel answers. DECIDED beside the trust plane whose document
/// enrols it, and before the first networked store is opened: an authority that cannot be
/// built is a startup refusal an operator reads without first waiting on a replay backend.
/// The evaluator is installed on the proxy by [`with_correlation`], once the proxy it decides
/// for exists; `Established` keeps the artifact and the posture together so the two cannot
/// come from different readings.
pub(super) fn authorization(
    start: &mut Startup<'_>,
) -> Result<Option<Arc<dyn AuthorizationEvaluator>>, String> {
    let (evaluator, state) = crate::authorization::capability::evaluator_for(
        start.config.state(),
        start.plans.trust.response_kid(),
        &start.config.config().audience,
    )?
    .into_parts();
    start.posture.declare(Seam::Authorization, state);
    Ok(evaluator)
}

/// ADR-MCPRE-050 + §5: assemble the RFC 9421 serving PEP with the async inner plane, the
/// authoritative replay tier and the delegated response signer the signing plane holds.
pub(super) fn serving_proxy(
    start: &Startup<'_>,
    seam: ServingSeam,
    replay: ReplayAdmission,
    pool: HttpInnerPool,
) -> Result<HttpProfileProxy, String> {
    Ok(HttpProfileProxy::new_delegated(
        seam.resolve_actor,
        seam.expected_audience,
        replay,
        Box::new(pool),
        RESPONSE_SIGNATURE_WINDOW_SECS,
        start.building.signing()?.signer(),
    ))
}

/// §5.1/§13.1: the verifier-local acceptance policy, projected by the freshness owner from
/// the same skew that drives the replay `retain_until`, so an admitted nonce is retained for
/// exactly as long as its signature can still be accepted — plus the Mode-A channel binding.
pub(super) fn with_verifier_policy(
    start: &mut Startup<'_>,
    proxy: HttpProfileProxy,
    binding: TransportBinding,
) -> HttpProfileProxy {
    let (mcp_transport, transport_state) = crate::serving_capabilities::mcp_transport_contract(
        start.config.state().mcp_transport_contract(),
    );
    let verifier_policy = start
        .config
        .state()
        .freshness()
        .verifier_policy()
        .with_mcp_transport(mcp_transport);
    start
        .posture
        .declare(Seam::McpTransportContract, transport_state);
    eprintln!(
        "mcp-re-proxy: freshness gate = created-{skew}s .. expires+{skew}s (RFC 9421 §5.1)",
        skew = verifier_policy.max_clock_skew()
    );
    proxy
        .with_verifier_policy(verifier_policy)
        .with_transport_binding(binding)
}

/// ADR-MCPS-035 / ADR-MCPRE-070 §2: the audit observer opens over the commitment
/// established earlier; OFF installs nothing, the serving path's default being the
/// no-emission posture. ADR-MCPRE-054: evidence retention follows, and opening its store is
/// effectful and refuses startup — the one capability here besides the commitment that can
/// return an error.
pub(super) fn with_audit_and_retention(
    start: &mut Startup<'_>,
    mut proxy: HttpProfileProxy,
    audit: crate::audit_commitment::EstablishedAudit,
) -> Result<HttpProfileProxy, String> {
    let state = start.config.state();
    let (audit, audit_state) =
        crate::serving_capabilities::audit_posture(state.audit(), audit)?.into_parts();
    if let Some(audit) = audit {
        proxy = proxy.with_audit_posture(audit);
    }
    start
        .posture
        .declare(Seam::SecurityAuditRecord, audit_state);

    let (retention, retention_state) =
        crate::serving_capabilities::evidence_retention(state.retention())?.into_parts();
    if let Some(retention) = retention {
        proxy = proxy.with_evidence_retention(Arc::new(retention));
    }
    start
        .posture
        .declare(Seam::EvidenceRetention, retention_state);
    Ok(proxy)
}

/// What travels with a request across hops: the verified-context carrier, ADR-MCPS-047's
/// shared MRTR continuation correlation store, and the authorization evaluator built earlier.
///
/// The continuation store connects over the SAME shared control runtime the fleet uses.
pub(super) fn with_correlation(
    start: &mut Startup<'_>,
    mut proxy: HttpProfileProxy,
    authorization: Option<Arc<dyn AuthorizationEvaluator>>,
) -> Result<HttpProfileProxy, String> {
    let state = start.config.state();
    let (verified_context, verified_context_state) =
        crate::serving_capabilities::verified_context_carrier(state.verified_context())
            .into_parts();
    if let Some(policy) = verified_context {
        proxy = proxy.with_verified_context_carrier(policy);
    }
    start
        .posture
        .declare(Seam::VerifiedContextCarrier, verified_context_state);

    let (continuation_store, continuation_state) =
        crate::serving_capabilities::mrtr_continuation_store(
            &state.continuation_control().continuation_plan(),
            start.building.control(),
        )?
        .into_parts();
    if let Some(store) = continuation_store {
        proxy = proxy.with_continuation_store(
            store,
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS,
        );
    }
    start
        .posture
        .declare(Seam::MrtrContinuationStore, continuation_state);

    if let Some(evaluator) = authorization {
        proxy = proxy.with_authorization(evaluator);
    }
    Ok(proxy)
}

/// MCPRE-493 §7: the admission-currency gate, connected over the shared control runtime.
pub(super) fn with_admission(
    start: &mut Startup<'_>,
    proxy: HttpProfileProxy,
) -> Result<HttpProfileProxy, String> {
    let state = start.config.state();
    let (admission, admission_state) = crate::serving_capabilities::admission_currency(
        state.admission(),
        state.freshness().max_clock_skew(),
        start.building.control(),
    )?
    .into_parts();
    let proxy = match admission {
        Some(enforcer) => proxy.with_admission_enforcer(enforcer),
        None => proxy,
    };
    start
        .posture
        .declare(Seam::AdmissionCurrency, admission_state);
    Ok(proxy)
}
