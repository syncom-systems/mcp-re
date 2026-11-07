// SPDX-License-Identifier: Apache-2.0
//! The shared trust-epoch plan: one interpretation of the epoch mechanism for every plane
//! that acts on it.

use crate::config_state::validation::ValidatedDeployment;

/// The shared trust-epoch mechanism, interpreted ONCE (CF-09).
///
/// Two planes act on this fact: trust flushes its cache when the epoch advances, and
/// delegated signing mints under the resulting label so an operator's `mcp-re-proxy trust-epoch advance` revokes
/// fleet-wide. They are consumers. Before this type they were two authorities — each
/// reading `--trust-epoch-redis-url`, each defaulting `--trust-epoch-key`, each with its
/// own build refusal — and the only reason they agreed was that they read the same fields
/// in the same way. Nothing made them.
///
/// The key arrives already defaulted by the trust-revocation classification
/// (`config_state::trust_revocation`, the one place `DEFAULT_TRUST_EPOCH_KEY` is applied),
/// and the plan CARRIES that single decision to both consumers: a default applied at two
/// sites is two decisions that happen to coincide.
///
/// The locator is readable only through [`TrustEpochPlan::networked_source`], which asks
/// the build question first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEpochPlan {
    /// No networked source. The trust cache runs at its declared bound, and delegated
    /// signing mints under the bare `--delegated-trust-epoch` label — the honest
    /// single-node shape, not a degraded one.
    NoNetworkChannel,
    /// A networked epoch counter at this location, under this key.
    Redis {
        /// Where the counter lives and the key holding it.
        locator: EpochLocator,
    },
}

/// Where a networked epoch counter lives, and the key holding it (already defaulted).
///
/// Readable only through `TrustEpochPlan::networked_source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochLocator {
    url: String,
    key: String,
}

/// A networked epoch source this build can establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishableEpochSource<'a> {
    url: &'a str,
    key: &'a str,
}

impl<'a> EstablishableEpochSource<'a> {
    /// Where the counter lives.
    pub fn url(&self) -> &'a str {
        self.url
    }

    /// The key holding the counter.
    pub fn key(&self) -> &'a str {
        self.key
    }
}

impl TrustEpochPlan {
    /// Project the plan from the classified trust-revocation state and the validated
    /// locator.
    ///
    /// Infallible: `PushNetworked` is the state that HAS a source, so layer A has already
    /// established both that this deployment may carry one and that it does.
    pub fn from_validated(config: &ValidatedDeployment) -> TrustEpochPlan {
        match config.state().trust_revocation().epoch_source() {
            Some(source) => TrustEpochPlan::Redis {
                locator: EpochLocator {
                    url: source.url().to_string(),
                    key: source.key().to_string(),
                },
            },
            None => TrustEpochPlan::NoNetworkChannel,
        }
    }

    /// The networked source a consumer may connect to: `Err` with the build refusal when
    /// this build cannot establish it, `None` when the plan has no networked source.
    pub fn networked_source(&self) -> Result<Option<EstablishableEpochSource<'_>>, String> {
        if let Some(refusal) = self.unsupported_by_build() {
            return Err(refusal);
        }
        match self {
            TrustEpochPlan::NoNetworkChannel => Ok(None),
            TrustEpochPlan::Redis { locator } => Ok(Some(EstablishableEpochSource {
                url: &locator.url,
                key: &locator.key,
            })),
        }
    }

    /// A networked plan for in-crate tests.
    #[cfg(test)]
    pub(crate) fn redis(url: &str, key: &str) -> TrustEpochPlan {
        TrustEpochPlan::Redis {
            locator: EpochLocator {
                url: url.to_string(),
                key: key.to_string(),
            },
        }
    }

    /// Why THIS BUILD cannot establish the plan, if it cannot — layer B, stated once.
    ///
    /// Both planes refused a configured epoch source in a build without a Redis client,
    /// in two places, with two different messages naming two different consequences. Each
    /// message was true and neither was complete, and which one an operator met was decided
    /// by materialization order. One refusal states both consequences.
    pub fn unsupported_by_build(&self) -> Option<String> {
        match self {
            TrustEpochPlan::NoNetworkChannel => None,
            TrustEpochPlan::Redis { .. } if cfg!(feature = "redis_replay") => None,
            TrustEpochPlan::Redis { .. } => Some(
                "--trust-epoch-redis-url requires a build with the `redis_replay` feature. \
                 Without it the trust cache has no networked invalidation channel, and \
                 delegated credentials would be minted under the bare --delegated-trust-epoch \
                 label — which the trust-epoch kill switch (`mcp-re-proxy trust-epoch \
                 advance`) cannot revoke. Refusing to start (fail closed, ADR-MCPRE-052 §7)"
                    .to_string(),
            ),
        }
    }
}
