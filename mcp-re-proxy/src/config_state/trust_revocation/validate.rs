// SPDX-License-Identifier: Apache-2.0
//! The violation predicates of the requested trust-revocation state, and the entry point
//! that classifies, checks and builds.
//!
//! The legality rules of [`super::TrustRevocationState`]'s state forms: check the cadence,
//! epoch-source and window columns of the state the request most nearly names, and build the
//! state only when no violation was produced.

use super::classify::{build, classify, RequestedState};
use super::TrustRevocationState;
use crate::deployment_request::{DeploymentRequest, RedactedLocator, TrustEpochStoreRequest};

/// The reload cadence the state requires, and the ceiling it must respect.
///
/// A separate predicate because the cadence is the whole revocation claim: a tier states
/// how fast a key removed from `--trust` stops resolving, and nothing resolves faster than
/// the file is re-read.
fn cadence_violations(state: RequestedState, config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    // Only `BoundedCache` may omit a cadence, and omitting it is legal.
    let Some(secs) = config.request_signer_currency.reload_secs() else {
        return out;
    };
    // Unconditional, like its CRL sibling: the cadence is the sleep between re-reads, so a
    // zero one re-reads `--trust` and rebuilds the signer directory continuously, on a
    // spinning thread. `BoundedCache` is included because it projects the same reload.
    if secs == 0 {
        out.push(
            "--trust-reload-secs 0 makes the trust reloader spin: the cadence is the sleep \
             between re-reads, so zero re-reads --trust and rebuilds the signer directory \
             continuously. Set a positive cadence, or omit the flag under \
             --revocation-tier bounded-cache to read --trust once at startup"
                .to_string(),
        );
        return out;
    }
    let (ceiling, claim) = match state {
        RequestedState::Live => (
            MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS,
            "--revocation-tier live states a window bounded by the re-read cadence (the \
             store is consulted on every verification)"
                .to_string(),
        ),
        RequestedState::PushInert { t_secs } | RequestedState::PushNetworked { t_secs } => (
            MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS.min(t_secs.max(1) as u64),
            format!(
                "--revocation-tier push:{t_secs} states a re-read-bounded window with a \
                 bounded {t_secs}s fallback"
            ),
        ),
        RequestedState::BoundedCache { t_secs } => (
            t_secs.max(1) as u64,
            format!(
                "--revocation-tier bounded-cache:{t_secs} states that cached trust \
                 lives at most {t_secs}s"
            ),
        ),
    };
    if secs > ceiling {
        out.push(format!(
            "--trust-reload-secs {secs} is longer than the revocation window the declared \
             tier claims: {claim}, but a key removed from --trust keeps resolving until the \
             file is re-read, which is every {secs}s. Set --trust-reload-secs <= {ceiling}, \
             or declare a tier whose window the deployment can keep"
        ));
    }
    out
}

/// The epoch-source columns: which states may carry one, and what shape it must have.
fn epoch_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    // Build-independent shape only. Whether the URL RESOLVES is layer C, and whether this
    // binary has a Redis client at all is layer B; both are materialization's to refuse.
    if let Some(url) = config
        .request_signer_currency
        .epoch()
        .and_then(TrustEpochStoreRequest::locator)
    {
        if !url.contains("://") {
            out.push(format!(
                "--trust-epoch-redis-url {} is not a URL: the trust-epoch source is \
                 what the trust-epoch kill switch (`mcp-re-proxy trust-epoch advance`) \
                 reaches, so a value that cannot name a store leaves delegated credentials \
                 unrevocable. Give a scheme-bearing URL such as redis://host:6379",
                RedactedLocator::of(url)
            ));
        }
    }
    out
}

/// `T` must be positive. Checked on the request type, not only by `RevocationTier::parse`,
/// because `DeploymentRequest` has public fields.
fn window_violation(state: RequestedState) -> Option<String> {
    let t_secs = match state {
        RequestedState::Live => return None,
        RequestedState::BoundedCache { t_secs }
        | RequestedState::PushInert { t_secs }
        | RequestedState::PushNetworked { t_secs } => t_secs,
    };
    (t_secs < 1)
        .then(|| format!("--revocation-tier window {t_secs}s is not a positive revocation window"))
}

/// Classify the requested trust-revocation state and check its four columns.
///
/// The state is returned alongside the violations rather than instead of them: a caller
/// accumulating across machines needs every violation, and a caller that finds none needs
/// the classification (CF-10 — classify, do not classify and discard).
///
/// `None` is returned exactly when a violation was produced — the state is withheld rather
/// than built carrying a refused value — so a `None` never travels without its reason.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<TrustRevocationState>, Vec<String>) {
    let requested = classify(config);
    let mut violations: Vec<String> = window_violation(requested).into_iter().collect();
    violations.extend(cadence_violations(requested, config));
    violations.extend(epoch_violations(config));
    let state = build(requested, config).filter(|_| violations.is_empty());
    (state, violations)
}

/// The ceiling on `--trust-reload-secs` for the tiers whose window is bounded by the
/// re-read cadence rather than by a cache lifetime (`live`, `push`).
///
/// Those tiers describe how fast a revoked request-signer key stops being honoured, and
/// the only thing that removes a key from the resolver on a running replica is the
/// `--trust` re-read. The cadence is therefore the real window, whatever the tier
/// string says. One minute bounds that window at the reload failure budget times 60s at
/// worst (`delivered_window`). It is this owner's policy ceiling: request signatures are
/// verified per request, so no connection lifetime bounds a request-signer revocation.
pub const MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS: u64 = 60;
