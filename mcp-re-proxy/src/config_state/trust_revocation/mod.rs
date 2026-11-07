// SPDX-License-Identifier: Apache-2.0
//! The `TrustRevocation` configuration machine — unit `proxy.trust_revocation_classification`.
//!
//! Four states, distinguished by the declared tier and by whether a networked epoch
//! source is configured:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `BoundedCache{T}` | — | epoch url, epoch key | `reload <= T` if set |
//! | `Live` | reload | epoch url, epoch key | `reload <= MAX_LIVE_OR_PUSH` |
//! | `PushInert{T}` | reload | epoch key | `reload <= min(MAX_LIVE_OR_PUSH, T)` |
//! | `PushNetworked{T}` | reload, epoch url | — | same, plus a scheme-bearing url |
//!
//! **Each state carries what its Required column names.** The three states that require a
//! cadence hold one, so they cannot be built without it and planning cannot project
//! "read once at startup" from a tier that claims the store is re-read. `PushNetworked`
//! additionally holds the epoch locator whose presence distinguishes it from `PushInert`,
//! and the epoch key already resolved against this machine's default. `BoundedCache`'s
//! cadence is optional, so it stays a validated request parameter.
//!
//! **The epoch source is a selector, not a parameter.** It is what distinguishes the last
//! two states, so a tier that cannot consume it does not merely ignore it — the request is
//! incoherent, and it is refused.
//!
//! This machine owns whether the epoch configuration is LEGAL. It does not own what the
//! configuration MEANS to a runtime plane: normalizing that is startup planning's job,
//! done once, and `TrustPlan` and `SigningPlane` are consumers of the one answer
//! (CF-09 — a fact may have two consumers, it must not have two authorities).

use crate::revocation_tier::RevocationTier;
use std::num::NonZeroU64;

mod classify;
mod epoch_source;
mod validate;

pub use epoch_source::EpochSource;
pub use validate::{classify_and_validate, MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS};

/// Which trust-revocation state a configuration requests, and what makes it inhabitable.
///
/// Each state carries the witnesses its own Required column names. Three of the four
/// require a reload cadence, so those three cannot be constructed without one — planning
/// therefore cannot project `ReadOnceAtStartup` from a tier whose whole claim is that the
/// store is re-read. `BoundedCache` carries the same fact as an `Option`, because its
/// column makes the cadence optional and the ABSENCE is itself a sub-posture. Carrying it
/// rather than leaving it in the request is what stops planning reconverting a raw value:
/// a `Some(0)` filtered back to `None` there would silently turn a refused request into a
/// different legal deployment.
///
/// The cadence is a `NonZeroU64` because layer A refuses zero: the cadence is the sleep
/// between re-reads, so a zero one re-reads `--trust` and rebuilds the signer directory
/// continuously. The rule and the type are the same fact — the type may encode the
/// invariant because the legality model states it, not instead of it.
/// The representation is private to this module. [`classify_and_validate`] is the only
/// producer and withholds the state whenever it produced a violation, so possessing one
/// means every rule of its state form held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRevocationState {
    kind: RevocationKind,
}

/// The four states, as the owner's own representation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RevocationKind {
    /// Tier 1 — cached active trust state lives at most `t_secs`.
    BoundedCache {
        /// The declared trust-propagation window.
        t_secs: i64,
        /// How often `--trust` is re-read, where the operator asked for that. OPTIONAL
        /// here and required by the other three: this is the one state whose claim holds
        /// without a re-read, so both refresh postures are legal and the absence is itself
        /// the sub-posture. Normalized, so planning never reconverts a raw cadence.
        reload_secs: Option<NonZeroU64>,
    },
    /// Tier 2 — the store is consulted on every verification.
    Live {
        /// How often `--trust` is re-read. Required: the tier's claim is that a removed
        /// key stops resolving near-instantly, and nothing resolves faster than the re-read.
        reload_secs: NonZeroU64,
    },
    /// Tier 3 with no epoch source: the push channel is absent, so the honest guarantee
    /// is the bounded-`T` fallback and nothing else.
    PushInert {
        /// The bounded-`T` fallback window.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: NonZeroU64,
    },
    /// Tier 3 with a networked epoch source: a revocation advances the epoch and the
    /// trust cache flushes within a poll interval.
    PushNetworked {
        /// The bounded-`T` fallback window, used when the channel is unhealthy.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: NonZeroU64,
        /// Where the epoch counter lives. Its presence is what distinguishes this state
        /// from `PushInert`, so the state that has one carries it.
        epoch_url: String,
        /// Which key holds the counter, already resolved against the default. Downstream
        /// cannot tell whether an operator named it.
        epoch_key: String,
    },
}

impl TrustRevocationState {
    /// A cadence witness from a literal, for tests and for callers that already hold a
    /// value layer A has accepted. Panics on zero, which layer A refuses.
    #[cfg(test)]
    pub(crate) fn cadence(secs: u64) -> NonZeroU64 {
        NonZeroU64::new(secs).expect("a cadence witness is non-zero")
    }

    /// Whether this state carries a networked epoch channel.
    ///
    /// The one question both `TrustPlan` and `SigningPlan` ask, answered from the
    /// classification rather than by re-reading the URL on each plane (CF-09).
    pub fn has_networked_epoch(&self) -> bool {
        matches!(self.kind, RevocationKind::PushNetworked { .. })
    }

    /// Where the epoch counter lives, or `None` when this state has no networked source.
    ///
    /// The projection replaces a match on the representation performed in planning. Both
    /// halves of the locator come back as one value, so no consumer can pair this
    /// deployment's store with another deployment's key.
    pub fn epoch_source(&self) -> Option<EpochSource<'_>> {
        match &self.kind {
            RevocationKind::PushNetworked {
                epoch_url,
                epoch_key,
                ..
            } => Some(EpochSource {
                url: epoch_url,
                key: epoch_key,
            }),
            _ => None,
        }
    }

    /// The declared tier, as the resolver builder's own type.
    ///
    /// A projection OUT of the classification, not a second reading of `--revocation-tier`:
    /// the two push states collapse back to one tier because the epoch source changes what
    /// is established, not which caching discipline the resolver applies. A plane that
    /// re-read the flag instead would be free to disagree with the state that was
    /// classified (CF-10).
    pub fn tier(&self) -> RevocationTier {
        match &self.kind {
            RevocationKind::BoundedCache { t_secs, .. } => {
                RevocationTier::BoundedCache { t_secs: *t_secs }
            }
            RevocationKind::Live { .. } => RevocationTier::Live,
            RevocationKind::PushInert { t_secs, .. }
            | RevocationKind::PushNetworked { t_secs, .. } => {
                RevocationTier::Push { t_secs: *t_secs }
            }
        }
    }

    /// Whether this state asks for a push channel that has no source behind it.
    ///
    /// The honest guarantee is then the bounded-`T` fallback and nothing else, which is a
    /// thing to SAY at startup — so it is named here rather than inferred at the surface
    /// from a channel that came back absent.
    pub fn push_channel_is_inert(&self) -> bool {
        matches!(self.kind, RevocationKind::PushInert { .. })
    }

    /// How often `--trust` is re-read, or `None` when the state's claim holds without a
    /// re-read.
    ///
    /// The projection replaces a match over three reload-bearing variants performed in
    /// planning. Which states require a cadence, and which one may legally omit it, is this
    /// machine's rule — a planner re-deciding it could project a reload-bearing state to
    /// read-once and contradict a tier whose whole claim is that the store is re-read.
    /// Layer A normalized the optional cadence, so there is no `Some(0)` left to filter.
    pub fn reload_cadence(&self) -> Option<NonZeroU64> {
        match &self.kind {
            RevocationKind::Live { reload_secs }
            | RevocationKind::PushInert { reload_secs, .. }
            | RevocationKind::PushNetworked { reload_secs, .. } => Some(*reload_secs),
            RevocationKind::BoundedCache { reload_secs, .. } => *reload_secs,
        }
    }

    /// The window the state claims, in seconds — `None` for `Live`, which caches nothing
    /// and is bounded by its re-read cadence alone.
    pub fn declared_window_secs(&self) -> Option<i64> {
        match &self.kind {
            RevocationKind::Live { .. } => None,
            RevocationKind::BoundedCache { t_secs, .. }
            | RevocationKind::PushInert { t_secs, .. }
            | RevocationKind::PushNetworked { t_secs, .. } => Some(*t_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    /// The posture a published tier plus an optional cadence names. A helper because the
    /// tier vocabulary is what the tests are written in, and the union is what the request
    /// holds — the mapping is the CLI adapter's job in production and this is its fixture
    /// twin.
    fn posture(tier: RevocationTier, reload_secs: Option<u64>) -> RequestSignerCurrencyRequest {
        match tier {
            RevocationTier::BoundedCache { t_secs } => RequestSignerCurrencyRequest::BoundedCache {
                t_secs,
                reload_secs,
            },
            RevocationTier::Live => RequestSignerCurrencyRequest::Live {
                reload_secs: reload_secs.unwrap_or_default(),
            },
            RevocationTier::Push { t_secs } => RequestSignerCurrencyRequest::Push {
                t_secs,
                reload_secs: reload_secs.unwrap_or_default(),
                epoch: TrustEpochStoreRequest::default(),
            },
        }
    }

    /// A pushing posture over one epoch source. Written through the request's own types,
    /// so a fixture cannot state an epoch source under a tier that reads none.
    fn pushing(
        t_secs: i64,
        reload_secs: u64,
        url: &str,
        key: Option<&str>,
    ) -> RequestSignerCurrencyRequest {
        RequestSignerCurrencyRequest::Push {
            t_secs,
            reload_secs,
            epoch: TrustEpochStoreRequest {
                source: Some(crate::deployment_request::TrustEpochSource::redis(
                    url,
                    key.map(str::to_string),
                )),
            },
        }
    }

    /// Build a state from the owner's own representation. In-module only: outside this
    /// module a state is obtainable solely from `classify_and_validate`.
    fn state(kind: RevocationKind) -> TrustRevocationState {
        TrustRevocationState { kind }
    }

    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{
        DeploymentRequest, RequestSignerCurrencyRequest, TrustEpochStoreRequest,
    };

    fn state_of(mutate: impl FnOnce(&mut DeploymentRequest)) -> TrustRevocationState {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
            .0
            .expect("the case names a state whose witnesses are present")
    }

    fn violations_of(mutate: impl FnOnce(&mut DeploymentRequest)) -> Vec<String> {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config).1
    }

    /// The defect this closes: a zero cadence reached the reload worker, which sleeps for
    /// the cadence and then re-reads. `Halt::sleep(Duration::from_secs(0))` sets a deadline
    /// already in the past and returns immediately, so `--trust` was re-read and the signer
    /// directory rebuilt continuously, on a spinning thread. The CRL machine refused the
    /// same input; this one did not.
    ///
    /// Every state is covered, `BoundedCache` included: its cadence is optional, but a
    /// cadence it DOES name projects the same reload as the other three.
    #[test]
    fn a_zero_cadence_is_a_spinning_reloader_in_every_state() {
        let tiers = [
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Live,
            RevocationTier::Push { t_secs: 30 },
        ];
        for tier in tiers {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier.clone(), Some(0));
            });
            assert!(
                violations.iter().any(|v| v.contains("spin")),
                "{tier:?} must refuse a zero cadence: {violations:?}"
            );
        }
    }

    /// The negative control for the guard above: one second is legal and stays legal. A
    /// guard written as `<= 0` on a signed type, or as a range that swallowed its own
    /// boundary, would refuse this and the test above would still pass.
    #[test]
    fn the_smallest_positive_cadence_is_admitted() {
        for tier in [RevocationTier::Live, RevocationTier::Push { t_secs: 30 }] {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier.clone(), Some(1));
            });
            assert!(
                violations.is_empty(),
                "{tier:?} with a 1s cadence must be admitted: {violations:?}"
            );
        }
        assert_eq!(
            state_of(|c| {
                c.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 1 };
            }),
            state(RevocationKind::Live {
                reload_secs: TrustRevocationState::cadence(1)
            })
        );
    }

    /// The guard is on the RUNTIME, not on argv. `DeploymentRequest` has public fields, so a caller
    /// that builds one in code reaches the same reloader — which is the altitude mistake
    /// `ValidatedDeployment` exists to correct, and the reason this is checked here rather than
    /// in the parser.
    #[test]
    fn a_programmatic_config_cannot_spin_the_trust_reloader() {
        let mut config = legal_config();
        config.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 0 };
        let refusal = crate::config_state::validation::ValidatedDeployment::try_from(config)
            .expect_err("a spinning reloader must not validate");
        assert!(refusal.contains("--trust-reload-secs 0"), "{refusal}");
    }

    // ---- the matrix: every legal state form is recognised AND accepted ----

    /// A legal form: the state it must be recognised as, and how to request it.
    type LegalForm = (TrustRevocationState, Box<dyn Fn(&mut DeploymentRequest)>);

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<LegalForm> = vec![
            (
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: None,
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        posture(RevocationTier::BoundedCache { t_secs: 60 }, None);
                }),
            ),
            (
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: Some(TrustRevocationState::cadence(60)),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        posture(RevocationTier::BoundedCache { t_secs: 60 }, Some(60));
                }),
            ),
            (
                state(RevocationKind::Live {
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        RequestSignerCurrencyRequest::Live { reload_secs: 5 };
                }),
            ),
            (
                state(RevocationKind::PushInert {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(30),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    // The INERT posture: a pushing tier that names no epoch source. Absence
                    // is what separates the two push states, and only this tier has a field
                    // for one to be absent from.
                    c.request_signer_currency =
                        posture(RevocationTier::Push { t_secs: 30 }, Some(30));
                }),
            ),
            (
                state(RevocationKind::PushNetworked {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(30),
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        pushing(30, 30, "redis://127.0.0.1:6379", Some("mcp-re:trust:epoch"));
                }),
            ),
        ];
        for (expected, mutate) in cases {
            let mut config = legal_config();
            mutate(&mut config);
            let (state, violations) = classify_and_validate(&config);
            assert_eq!(
                state,
                Some(expected.clone()),
                "classified as the wrong state"
            );
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    #[test]
    fn a_refused_request_yields_no_state() {
        let ceiling = RequestSignerCurrencyRequest::Live {
            reload_secs: MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS + 1,
        };
        let not_a_url = RequestSignerCurrencyRequest::Push {
            t_secs: 30,
            reload_secs: 30,
            epoch: TrustEpochStoreRequest {
                source: Some(crate::deployment_request::TrustEpochSource::redis(
                    "127.0.0.1:6379",
                    None,
                )),
            },
        };
        for posture in [ceiling, not_a_url] {
            let mut config = legal_config();
            config.request_signer_currency = posture;
            let (state, violations) = classify_and_validate(&config);
            assert_eq!(state, None, "a refused request must not yield a state");
            assert!(!violations.is_empty());
        }
    }

    #[test]
    fn a_non_positive_window_is_refused_on_the_runtime_type() {
        let postures = [
            RequestSignerCurrencyRequest::BoundedCache {
                t_secs: 0,
                reload_secs: None,
            },
            RequestSignerCurrencyRequest::Push {
                t_secs: -5,
                reload_secs: 1,
                epoch: TrustEpochStoreRequest::default(),
            },
        ];
        for posture in postures {
            let mut config = legal_config();
            config.request_signer_currency = posture;
            let (state, violations) = classify_and_validate(&config);
            assert_eq!(state, None);
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("is not a positive revocation window")),
                "{violations:?}"
            );
        }
        let mut config = legal_config();
        config.request_signer_currency = RequestSignerCurrencyRequest::BoundedCache {
            t_secs: 0,
            reload_secs: None,
        };
        let refusal = crate::config_state::validation::ValidatedDeployment::try_from(config)
            .expect_err("a non-positive window must not validate");
        assert!(
            refusal.contains("is not a positive revocation window"),
            "{refusal}"
        );
    }

    // ---- classification is asserted, not only the verdict ----

    #[test]
    fn the_epoch_source_is_what_splits_push_in_two() {
        let inert = state_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest::default(),
            };
        });
        let networked = state_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest {
                    source: Some(crate::deployment_request::TrustEpochSource::redis(
                        "redis://127.0.0.1:6379",
                        None,
                    )),
                },
            };
        });
        assert!(!inert.has_networked_epoch());
        assert!(networked.has_networked_epoch());
        assert_ne!(inert, networked, "the same tier, two different states");
    }

    /// The projection back to the resolver's own type is total, and the two push states
    /// collapse to one tier: the epoch source changes what gets ESTABLISHED, not which
    /// caching discipline the resolver applies.
    #[test]
    fn the_state_projects_back_to_the_tier_the_resolver_is_built_from() {
        for (state, expected) in [
            (
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: None,
                }),
                RevocationTier::BoundedCache { t_secs: 60 },
            ),
            (
                state(RevocationKind::Live {
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                RevocationTier::Live,
            ),
            (
                state(RevocationKind::PushInert {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                RevocationTier::Push { t_secs: 30 },
            ),
            (
                state(RevocationKind::PushNetworked {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                }),
                RevocationTier::Push { t_secs: 30 },
            ),
        ] {
            assert_eq!(state.tier(), expected, "{state:?}");
        }
        assert!(state(RevocationKind::PushInert {
            t_secs: 30,
            reload_secs: crate::config_state::TrustRevocationState::cadence(5)
        })
        .push_channel_is_inert());
        assert!(!state(RevocationKind::PushNetworked {
            t_secs: 30,
            reload_secs: crate::config_state::TrustRevocationState::cadence(5),
            epoch_url: "redis://127.0.0.1:6379".to_string(),
            epoch_key: "mcp-re:trust:epoch".to_string()
        })
        .push_channel_is_inert());
    }

    #[test]
    fn live_declares_no_bounded_window() {
        assert_eq!(
            state_of(|c| {
                c.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 5 };
            })
            .declared_window_secs(),
            None
        );
    }

    // ---- required parameters ----

    // The X8 test left this module with the state it examined. An epoch source under a
    // tier that reads none is not a configuration any more: only the pushing posture has a
    // field for one (ADR-MCPRE-067 §7). The argv form survives and
    // `cli::currency_flags::tests::an_epoch_source_under_a_tier_that_reads_none_is_refused`
    // pins the same sentence.

    #[test]
    fn bounded_cache_does_not_require_a_cadence() {
        assert!(violations_of(|c| {
            c.request_signer_currency = posture(RevocationTier::BoundedCache { t_secs: 60 }, None);
        })
        .is_empty());
    }

    #[test]
    fn push_networked_requires_its_url_to_be_a_url() {
        let violations = violations_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest {
                    source: Some(crate::deployment_request::TrustEpochSource::redis(
                        "127.0.0.1:6379",
                        None,
                    )),
                },
            };
        });
        assert!(
            violations.iter().any(|v| v.contains("is not a URL")),
            "{violations:?}"
        );
    }

    /// The clause fires exactly when the value has no `://`, which is the shape a
    /// credential-bearing typo takes. It names the locator rather than echoing it.
    #[test]
    fn the_epoch_locator_refusal_does_not_echo_a_credential() {
        let violations = violations_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest {
                    source: Some(crate::deployment_request::TrustEpochSource::redis(
                        "mats:hunter2@redis.internal:6379",
                        None,
                    )),
                },
            };
        });
        let refusal = violations
            .iter()
            .find(|v| v.contains("--trust-epoch-redis-url"))
            .expect("a value that names no store is refused");
        assert!(
            !refusal.contains("hunter2"),
            "the password reached the diagnostic: {refusal}"
        );
    }

    // ---- forbidden parameters: presence carries intent (CF-04) ----

    // CF-04 — an epoch key naming a place in a store this configuration does not have —
    // has no test here any more, and its absence is the result. The coordinate travels
    // inside `TrustEpochSource`, so a key with no store cannot be constructed and the
    // clause has no configuration to examine. The argv form is still statable, and
    // `cli::storage_flags` refuses it with the same sentence.

    // ---- guards ----

    #[test]
    fn each_state_holds_the_cadence_to_the_window_it_claims() {
        for (tier, cadence) in [
            (RevocationTier::Live, MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS + 1),
            (RevocationTier::Push { t_secs: 10 }, 11),
            (RevocationTier::BoundedCache { t_secs: 30 }, 31),
        ] {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier, Some(cadence));
            });
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("is longer than the revocation window")),
                "cadence {cadence} accepted: {violations:?}"
            );
        }
    }

    #[test]
    fn a_push_window_narrower_than_the_cadence_ceiling_binds_instead_of_it() {
        // `push:10` claims a 10s fallback, so 30s is refused even though it is inside the
        // general cadence ceiling. The tighter of the two claims is the one that binds.
        const { assert!(MAX_LIVE_OR_PUSH_TRUST_RELOAD_SECS > 30) };
        let violations = violations_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 10,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest::default(),
            };
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("is longer than the revocation window")),
            "{violations:?}"
        );
    }
}
