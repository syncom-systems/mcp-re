// SPDX-License-Identifier: Apache-2.0
//! The connection bounds — unit `proxy.connection_bounds`.
//!
//! Not a deployment machine: there is no posture here, no control that is on in one state
//! and off in another. It is a RESOLVED FACT — layer A has answered whether the five
//! quantities that bound one connection's life are all in force, and refused the
//! deployment when one is not.
//!
//! | quantity | flag | what a disabled value would remove |
//! |---|---|---|
//! | read timeout | `--read-timeout-secs` | the per-read slow-loris bound |
//! | write timeout | `--write-timeout-secs` | the bound on a peer that stops reading |
//! | request deadline | `--request-deadline-secs` | the aggregate read-phase bound |
//! | drain window | `--drain-grace-secs` | the time an admitted request has to finish on SIGTERM |
//! | connection ceiling | `--max-connections` | the bound on buffering ahead of the verify gate |
//!
//! The request states each one with absence representable — a timeout of `0` parses to
//! `None`, the disabled posture — so the refusal can name the flag an operator typed.
//! [`ConnectionBounds`] cannot hold an absent or zero bound, so everything downstream reads
//! a `Duration` and never re-proves that one is present.
//!
//! # Two claims, two producers
//!
//! | producer | what holding the value means |
//! |---|---|
//! | [`ConnectionBounds::from_limits`] | every bound is in force |
//! | [`classify_and_validate`] | that, and the drain window covers the request deadline |
//!
//! The second is the k8s invariant `request_deadline <= drain_grace <
//! terminationGracePeriodSeconds`, a fact about a DEPLOYMENT. The serving path does not
//! need it to stay bounded — the drain ends at the grace whatever the deadline is — so an
//! embedder driving `async_serve` directly may run a window shorter than the deadline, and
//! the drain tests do exactly that to show the grace alone bounds exit. A deployment cannot:
//! its bounds come only from the classifier.

use std::num::NonZeroUsize;
use std::time::Duration;

use crate::deployment_request::DeploymentRequest;
use crate::deployment_request::ServerLimits;

mod refusal;

use refusal::Cover;

/// The default for each of the three socket timeouts: `--read-timeout-secs`,
/// `--write-timeout-secs` and `--request-deadline-secs`.
///
/// One constant, two readers: this owner's [`Default`] and [`ServerLimits::default`], which
/// must agree so that a `ServerLimits` built directly resolves to the bounds a default
/// `ServerOptions` carries.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The default drain window, `--drain-grace-secs`. Equal to the default request deadline,
/// so the default bounds satisfy `request_deadline <= drain_grace`.
pub const DEFAULT_DRAIN_GRACE: Duration = Duration::from_secs(30);

/// The default concurrent-connection ceiling, `--max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// The ceiling as a value whose non-zeroness is a BUILD-TIME fact: a `const` initializer is
/// evaluated by the compiler, so a zero default stops the build rather than panicking.
const DEFAULT_MAX_CONNECTIONS_NONZERO: NonZeroUsize =
    match NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS) {
        Some(ceiling) => ceiling,
        None => panic!("DEFAULT_MAX_CONNECTIONS must be non-zero"),
    };

/// The five bounds on one connection's life, every one of them in force.
///
/// The representation is private to this module, and both producers take operator input
/// through the same checks, so possessing one IS the statement that no bound is disabled. A
/// value from [`classify_and_validate`] also has a drain window covering the request deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionBounds {
    read_timeout: Duration,
    write_timeout: Duration,
    request_deadline: Duration,
    drain_grace: Duration,
    max_connections: NonZeroUsize,
}

impl Default for ConnectionBounds {
    /// The bounds a default [`ServerLimits`] resolves to.
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_TIMEOUT,
            write_timeout: DEFAULT_TIMEOUT,
            request_deadline: DEFAULT_TIMEOUT,
            drain_grace: DEFAULT_DRAIN_GRACE,
            max_connections: DEFAULT_MAX_CONNECTIONS_NONZERO,
        }
    }
}

impl ConnectionBounds {
    /// Resolve the bounds from the limits a request states, or every refusal that prevents it.
    ///
    /// Public, and still a seal: construction refuses every disabled bound, so an embedding
    /// binary or an integration test cannot hold a bound that is off. It does not require the
    /// drain window to cover the request deadline; that is a deployment rule, which
    /// [`classify_and_validate`] adds.
    pub fn from_limits(limits: &ServerLimits) -> Result<Self, Vec<String>> {
        Self::resolve(limits, Cover::NotRequired)
    }

    /// The refusals arrive in the order an operator reads them — the ceiling, the drain
    /// window, then the three timeouts.
    fn resolve(limits: &ServerLimits, cover: Cover) -> Result<Self, Vec<String>> {
        let mut refusals = refusal::ceiling(limits);
        refusals.extend(refusal::drain_window(limits, cover));
        refusals.extend(refusal::slow_loris(limits));
        let (
            Some(read_timeout),
            Some(write_timeout),
            Some(request_deadline),
            Some(max_connections),
        ) = (
            limits.read_timeout,
            limits.write_timeout,
            limits.request_deadline,
            NonZeroUsize::new(limits.max_concurrent_connections),
        )
        else {
            return Err(refusals);
        };
        if !refusals.is_empty() {
            return Err(refusals);
        }
        Ok(Self {
            read_timeout,
            write_timeout,
            request_deadline,
            drain_grace: limits.drain_grace,
            max_connections,
        })
    }

    /// The per-read bound on one socket, and the timeout the inner plane applies to a backend.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// The bound on a peer that has stopped reading.
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    /// The aggregate wall-clock bound over a request's whole read phase: the TLS handshake,
    /// the header block and the body.
    pub fn request_deadline(&self) -> Duration {
        self.request_deadline
    }

    /// How long a connection may carry no request. It is the request deadline: a header block
    /// that has not arrived inside the deadline belongs to a request the deadline would refuse
    /// anyway, so HTTP/1's header read and HTTP/2's idle watch share that one answer.
    pub fn idle_bound(&self) -> Duration {
        self.request_deadline
    }

    /// How long a stopping core waits for its in-flight requests. At least the request
    /// deadline, so every admitted request can finish inside it.
    pub fn drain_grace(&self) -> Duration {
        self.drain_grace
    }

    /// How many connections one core serves at once.
    pub fn max_connections(&self) -> NonZeroUsize {
        self.max_connections
    }
}

/// Resolve the bounds a deployment states.
///
/// With any refusal there is no coherent set of bounds, so the value gates construction rather
/// than being reported beside a usable one.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<ConnectionBounds>, Vec<String>) {
    match ConnectionBounds::resolve(&config.limits, Cover::Required) {
        Ok(bounds) => (Some(bounds), Vec::new()),
        Err(refusals) => (None, refusals),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ServerLimits {
        ServerLimits::default()
    }

    #[test]
    fn the_default_limits_resolve_to_the_default_bounds() {
        assert_eq!(
            ConnectionBounds::from_limits(&limits()),
            Ok(ConnectionBounds::default())
        );
    }

    #[test]
    fn a_resolved_bound_is_the_value_the_request_stated() {
        let bounds = ConnectionBounds::from_limits(&ServerLimits {
            read_timeout: Some(Duration::from_secs(7)),
            write_timeout: Some(Duration::from_secs(8)),
            request_deadline: Some(Duration::from_secs(9)),
            drain_grace: Duration::from_secs(10),
            max_concurrent_connections: 11,
            ..limits()
        })
        .expect("legal bounds");
        assert_eq!(bounds.read_timeout(), Duration::from_secs(7));
        assert_eq!(bounds.write_timeout(), Duration::from_secs(8));
        assert_eq!(bounds.request_deadline(), Duration::from_secs(9));
        assert_eq!(bounds.idle_bound(), Duration::from_secs(9));
        assert_eq!(bounds.drain_grace(), Duration::from_secs(10));
        assert_eq!(bounds.max_connections().get(), 11);
    }

    #[test]
    fn a_zero_connection_ceiling_is_refused() {
        let refusals = ConnectionBounds::from_limits(&ServerLimits {
            max_concurrent_connections: 0,
            ..limits()
        })
        .expect_err("a zero ceiling is refused");
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert!(refusals[0].contains("--max-connections 0"), "{refusals:?}");
    }

    #[test]
    fn each_disabled_timeout_is_refused_by_its_own_flag() {
        let refusals = ConnectionBounds::from_limits(&ServerLimits {
            read_timeout: None,
            write_timeout: None,
            request_deadline: None,
            ..limits()
        })
        .expect_err("disabled timeouts are refused");
        let flags: Vec<&str> = refusals
            .iter()
            .filter_map(|r| r.split_whitespace().next())
            .collect();
        assert_eq!(
            flags,
            [
                "--read-timeout-secs",
                "--write-timeout-secs",
                "--request-deadline-secs"
            ]
        );
    }

    fn deployment(limits: ServerLimits) -> (Option<ConnectionBounds>, Vec<String>) {
        let mut config = crate::config_state::test_support::legal_config();
        config.limits = limits;
        classify_and_validate(&config)
    }

    #[test]
    fn a_deployment_whose_drain_window_misses_the_request_deadline_is_refused() {
        let short = ServerLimits {
            request_deadline: Some(Duration::from_secs(60)),
            drain_grace: Duration::from_secs(30),
            ..limits()
        };
        let (bounds, refusals) = deployment(short.clone());
        assert_eq!(bounds, None);
        assert!(
            refusals[0].contains("shorter than --request-deadline-secs"),
            "{refusals:?}"
        );
        let (bounds, refusals) = deployment(ServerLimits {
            drain_grace: Duration::from_secs(60),
            ..short.clone()
        });
        assert!(bounds.is_some() && refusals.is_empty(), "{refusals:?}");
        assert!(
            ConnectionBounds::from_limits(&short).is_ok(),
            "outside a deployment the grace bounds the drain on its own"
        );
    }

    #[test]
    fn a_zero_drain_window_is_refused_once() {
        let refusals = ConnectionBounds::from_limits(&ServerLimits {
            drain_grace: Duration::ZERO,
            ..limits()
        })
        .expect_err("a zero window is refused");
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert!(refusals[0].contains("--drain-grace-secs 0"), "{refusals:?}");
    }

    #[test]
    fn an_unrepresentable_drain_window_is_refused() {
        let refusals = ConnectionBounds::from_limits(&ServerLimits {
            drain_grace: Duration::from_secs(u64::MAX),
            ..limits()
        })
        .expect_err("an unrepresentable window is refused");
        assert!(
            refusals.iter().any(|r| r.contains("ceiling")),
            "{refusals:?}"
        );
        assert!(ConnectionBounds::from_limits(&ServerLimits {
            request_deadline: Some(Duration::from_secs(86_400)),
            drain_grace: Duration::from_secs(86_400),
            ..limits()
        })
        .is_ok());
    }

    #[test]
    fn the_refusals_arrive_ceiling_then_drain_then_timeouts() {
        let refusals = ConnectionBounds::from_limits(&ServerLimits {
            max_concurrent_connections: 0,
            drain_grace: Duration::ZERO,
            read_timeout: None,
            ..limits()
        })
        .expect_err("three refusals");
        assert!(refusals[0].starts_with("--max-connections"), "{refusals:?}");
        assert!(
            refusals[1].starts_with("--drain-grace-secs"),
            "{refusals:?}"
        );
        assert!(
            refusals[2].starts_with("--read-timeout-secs"),
            "{refusals:?}"
        );
    }

    #[test]
    fn the_classifier_resolves_the_request_limits() {
        let config = crate::config_state::test_support::legal_config();
        let (bounds, refusals) = classify_and_validate(&config);
        assert!(refusals.is_empty(), "{refusals:?}");
        assert_eq!(
            bounds,
            ConnectionBounds::from_limits(&config.limits).ok(),
            "the classifier is the owner's own constructor over the request"
        );
    }
}
