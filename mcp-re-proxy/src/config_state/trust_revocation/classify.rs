// SPDX-License-Identifier: Apache-2.0
//! Which state a deployment request names, and the state value built once it is legal.
//!
//! Split from the violation predicates so classification stays total and the one place that
//! writes the private representation is small enough to read whole.

use super::RevocationKind;
use super::TrustRevocationState;
use crate::deployment_request::{DeploymentRequest, RequestSignerCurrencyRequest};
use std::num::NonZeroU64;

/// Which state the request most nearly names, before its witnesses are known to be present.
///
/// Separate from [`TrustRevocationState`] so classification can stay total. A classifier
/// that could fail would have to answer "which state is this?" and "is that state legal?"
/// at once, and the second answer is what the caller accumulates across machines — so a
/// missing cadence is reported as a violation of the state it most nearly requests, with
/// that state's own ceiling, rather than as an unclassifiable config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestedState {
    BoundedCache { t_secs: i64 },
    Live,
    PushInert { t_secs: i64 },
    PushNetworked { t_secs: i64 },
}

/// Recognise the requested state. Total: every `DeploymentRequest` names one.
///
/// Total on purpose. A classifier that could fail would have to answer "which state is
/// this?" and "is that state legal?" at once, and the second answer is what the caller
/// accumulates across machines — so an illegal combination is reported as a violation of
/// the state it most nearly requests, not as an unclassifiable config.
pub(super) fn classify(config: &DeploymentRequest) -> RequestedState {
    match &config.request_signer_currency {
        RequestSignerCurrencyRequest::BoundedCache { t_secs, .. } => {
            RequestedState::BoundedCache { t_secs: *t_secs }
        }
        RequestSignerCurrencyRequest::Live { .. } => RequestedState::Live,
        RequestSignerCurrencyRequest::Push { t_secs, epoch, .. } => {
            // The two push states differ by whether an epoch source is named, and only the
            // pushing posture has a field for one — which is what relation X8 used to have
            // to enforce across two independent fields.
            if epoch.source.is_some() {
                RequestedState::PushNetworked { t_secs: *t_secs }
            } else {
                RequestedState::PushInert { t_secs: *t_secs }
            }
        }
    }
}

/// Build the state, once its witnesses are known to be present.
///
/// Its `?`s cannot fire on an admitted request — a zero cadence is refused by
/// `cadence_violations`, and `classify` chose `PushNetworked` only because the epoch
/// source is present.
pub(super) fn build(
    requested: RequestedState,
    config: &DeploymentRequest,
) -> Option<TrustRevocationState> {
    // A cadence that is present and zero names no legal state at all, so `build` yields
    // nothing rather than an absence — `Some(0)` must never become "no reload requested".
    let cadence = match config.request_signer_currency.reload_secs() {
        None => None,
        Some(secs) => Some(NonZeroU64::new(secs)?),
    };
    Some(TrustRevocationState {
        kind: match requested {
            RequestedState::BoundedCache { t_secs } => RevocationKind::BoundedCache {
                t_secs,
                reload_secs: cadence,
            },
            RequestedState::Live => RevocationKind::Live {
                reload_secs: cadence?,
            },
            RequestedState::PushInert { t_secs } => RevocationKind::PushInert {
                t_secs,
                reload_secs: cadence?,
            },
            RequestedState::PushNetworked { t_secs } => {
                let source = config.request_signer_currency.epoch()?.source.as_ref()?;
                RevocationKind::PushNetworked {
                    t_secs,
                    reload_secs: cadence?,
                    epoch_url: source.locator().to_string(),
                    // The default belongs to this machine, so it is applied here and nothing
                    // downstream can tell an omitted key from a named one.
                    epoch_key: source
                        .key()
                        .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY)
                        .to_string(),
                }
            }
        },
    })
}
