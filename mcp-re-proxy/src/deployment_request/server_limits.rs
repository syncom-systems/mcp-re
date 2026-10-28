// SPDX-License-Identifier: Apache-2.0
//! The connection resource limits a deployment requests, and the part of them serving reads.

use std::num::NonZeroUsize;
use std::time::Duration;

/// Resource limits applied to every served connection — the blocking server's
/// defense against slow-loris, oversized-request, and connection-exhaustion
/// denial of service. Every limit fails closed: a connection that exceeds one is
/// dropped (or never accepted), never served partially.
///
/// The three timeouts, the connection ceiling and the drain window are the REQUEST: a
/// disabled one is representable so the boundary can refuse it by name. Serving reads them
/// from [`ServerOptions::connection_bounds`](crate::tls::ServerOptions::connection_bounds),
/// which holds them resolved and in force, and the connection age from
/// [`ServerOptions::client_credential_window`](crate::tls::ServerOptions::client_credential_window),
/// and the two size limits from the [`ServedLimits`] this request projects.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Maximum bytes accepted before the end-of-headers marker. Caps header
    /// floods and unterminated header streams.
    pub max_header_bytes: usize,
    /// Maximum request body (`Content-Length`, and bytes actually read). Caps
    /// oversized payloads.
    pub max_body_bytes: usize,
    /// Per-socket read timeout (covers a stalled TLS handshake and slow-loris
    /// body trickling, since reading drives the handshake). `None` disables.
    pub read_timeout: Option<Duration>,
    /// AGGREGATE wall-clock deadline over the WHOLE server read phase (TLS
    /// handshake + HTTP header block + body), the server-side mirror of
    /// mcp-re-transport's `DeadlineStream` (MCPS-094) and bounded response read
    /// (MCPS-093). The per-socket `read_timeout` bounds each INDIVIDUAL read, but a
    /// peer trickling one byte just under that timeout resets the per-read
    /// inactivity timer on every byte and can extend a single connection's total
    /// lifetime without bound (slow-loris below the per-read threshold), holding a
    /// serve thread. This caps the TOTAL handshake+request read wall-clock; once it
    /// elapses the next read fails closed (the connection is dropped). `None`
    /// disables the aggregate bound, preserving the per-read-only semantics.
    pub request_deadline: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum simultaneously-served connections in the threaded [`serve`] loop.
    /// Connections beyond the cap are dropped (TCP-accepted then closed) rather
    /// than queued unboundedly.
    pub max_concurrent_connections: usize,
    /// MCPRE-115 (ADR-MCPRE-051 §6): the BOUNDED GRACE WINDOW for graceful drain on
    /// the async serving path. On shutdown each per-core [`serve`] loop stops
    /// accepting and then waits up to this long for its IN-FLIGHT requests to
    /// complete before returning (after which the runtime is dropped and any
    /// still-running request is abandoned). Each in-flight request is ALSO bounded by
    /// `request_deadline`, so with `drain_grace >= request_deadline` every admitted
    /// request finishes within the window — zero abandoned. Size it UNDER the
    /// deployment's k8s `terminationGracePeriodSeconds` and AT OR ABOVE
    /// `request_deadline`: `request_deadline <= drain_grace < terminationGracePeriodSeconds`.
    /// Idle keep-alive connections carry no in-flight request and do not extend the
    /// drain — an idle drain returns promptly.
    pub drain_grace: Duration,
    /// The requested maximum age of one mTLS connection. The boundary resolves it with
    /// the certificate lifetime into
    /// [`ClientCredentialWindow`](crate::config_state::ClientCredentialWindow), and the
    /// serving path reads [`ServerOptions::client_credential_window`](crate::tls::ServerOptions::client_credential_window), never this field.
    pub max_connection_age: Option<Duration>,
    /// The rate and burst of the listener's delegated handshake-signature budget. Read
    /// once, by [`ChannelEstablishmentPlan`](crate::startup_plan::ChannelEstablishmentPlan).
    pub tls_handshake_signing: crate::delegated_tls::HandshakeSignCapacity,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            read_timeout: Some(crate::config_state::connection_bounds::DEFAULT_TIMEOUT),
            request_deadline: Some(crate::config_state::connection_bounds::DEFAULT_TIMEOUT),
            write_timeout: Some(crate::config_state::connection_bounds::DEFAULT_TIMEOUT),
            max_concurrent_connections:
                crate::config_state::connection_bounds::DEFAULT_MAX_CONNECTIONS,
            // >= request_deadline (so every admitted request can finish) and, in
            // production, < k8s terminationGracePeriodSeconds.
            drain_grace: crate::config_state::connection_bounds::DEFAULT_DRAIN_GRACE,
            // Bounds how long a peer keeps serving on a certificate validated only at
            // its handshake. 300s is well inside the 1h certificate-lifetime
            // ceiling and short enough that a CRL reload takes effect within one
            // cadence, while being long enough that re-handshake cost is negligible.
            max_connection_age: Some(Duration::from_secs(300)),
            tls_handshake_signing: crate::delegated_tls::HandshakeSignCapacity::default(),
        }
    }
}

impl ServerLimits {
    /// What serving reads from these limits, with each core's share of the admission limit
    /// `basis` resolved, over `shards` cores.
    ///
    /// The timeouts, the connection ceiling, the drain window and the connection age are not
    /// carried: their owners resolved them, and serving reads them there.
    pub fn served(
        &self,
        basis: crate::config_state::in_flight_limit::InFlightLimitBasis,
        shards: NonZeroUsize,
    ) -> ServedLimits {
        ServedLimits {
            max_header_bytes: self.max_header_bytes,
            max_body_bytes: self.max_body_bytes,
            max_in_flight_requests: Some(basis.per_core_ceiling(shards).get()),
        }
    }
}

/// The limits serving reads that no other owner holds: the two size ceilings, and the
/// per-core in-flight ceiling.
///
/// Everything else a [`ServerLimits`] states has an owner that resolved it, so a serving
/// value carrying it would be a second copy that could disagree with the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedLimits {
    /// Maximum bytes accepted before the end-of-headers marker. Caps header floods and
    /// unterminated header streams.
    pub max_header_bytes: usize,
    /// Maximum request body (`Content-Length`, and bytes actually read). Caps oversized
    /// payloads.
    pub max_body_bytes: usize,
    /// MCPRE-114 (ADR-MCPRE-051 §1): per-core bounded ADMISSION control — the
    /// maximum number of requests being served CONCURRENTLY on one core (async
    /// serving path). A request that arrives while the ceiling is full is rejected
    /// fail-closed with `503 Service Unavailable` BEFORE the handler runs, rather
    /// than queued without bound — so tail latency stays bounded under overload
    /// instead of degrading unboundedly. `None` disables the ceiling (unbounded
    /// in-flight; the historical behavior). Bounds only the async
    /// (`async_serve`) path; the blocking loop bounds concurrency via the connection
    /// ceiling.
    ///
    /// # RESOLVED, not requested
    ///
    /// This is not what an operator wrote. The admission limit is stated once, in
    /// [`DeploymentRequest::in_flight_limit`](crate::deployment_request::DeploymentRequest::in_flight_limit), which can express
    /// per-core, fleet-wide, or nothing at all; the boundary resolves that to a basis, and
    /// [`ServerLimits::served`] takes the per-core answer from it and the resolved shard count. The fleet writes the same
    /// answer for each core it starts, so a caller driving the fleet directly is held to the
    /// basis too.
    ///
    /// The fail-safe default is the same constant the basis resolves an unstated limit to,
    /// so an embedder driving `async_serve` with no `DeploymentRequest` is bounded on exactly
    /// the same terms.
    pub max_in_flight_requests: Option<usize>,
}

impl Default for ServedLimits {
    fn default() -> Self {
        let requested = ServerLimits::default();
        ServedLimits {
            max_header_bytes: requested.max_header_bytes,
            max_body_bytes: requested.max_body_bytes,
            // A DEFENSIBLE per-core ceiling rather than the unbounded historical
            // default. Unbounded meant one peer holding a valid client certificate
            // could multiplex unbounded HTTP/2 streams, each buffering up to
            // `max_body_bytes` BEFORE the verify gate — attacker-controlled memory
            // with zero authenticated requests, and it also left hyper's HTTP/2
            // `max_concurrent_streams` unset.
            //
            // MATCHED TO the default connection ceiling on purpose. That cap already
            // admitted 256 concurrent connections per core, so one in-flight request
            // per admitted connection tightens nothing that was previously allowed —
            // it just stops the H2 multiplexer exceeding it. A smaller number would be
            // a throughput policy rather than a memory bound, and it would shed inside
            // the ADR-MCPRE-051 §7 envelope (concurrency 128), which is a load-shaping
            // decision no default should make silently.
            max_in_flight_requests: Some(
                crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ServedLimits, ServerLimits};
    use crate::config_state::in_flight_limit::InFlightLimitBasis;
    use crate::config_state::ConnectionBounds;
    use std::num::NonZeroUsize;

    /// The defaults resolve to the bounds a default `ServerOptions` carries: the two
    /// owners read the same constants, so an embedder that builds either gets the other.
    #[test]
    fn the_default_limits_resolve_to_the_default_connection_bounds() {
        assert_eq!(
            ConnectionBounds::from_limits(&ServerLimits::default()),
            Ok(ConnectionBounds::default())
        );
    }

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("not zero")
    }

    /// Serving is handed the two size ceilings as requested and each core's share of the
    /// basis, and nothing another owner resolved.
    #[test]
    fn the_served_limits_carry_the_sizes_and_each_cores_share() {
        let requested = ServerLimits {
            max_header_bytes: 1000,
            max_body_bytes: 2000,
            ..ServerLimits::default()
        };
        let fleet_total = InFlightLimitBasis::FleetTotal { requests: nz(1000) };
        assert_eq!(
            requested.served(fleet_total, nz(3)),
            ServedLimits {
                max_header_bytes: 1000,
                max_body_bytes: 2000,
                max_in_flight_requests: Some(334),
            },
            "a fleet-wide target is divided across the cores, rounding up"
        );
        let per_core = InFlightLimitBasis::PerCore { requests: nz(7) };
        assert_eq!(
            requested.served(per_core, nz(3)).max_in_flight_requests,
            Some(7)
        );
    }

    /// An embedder's default serving limits are the request defaults with the per-core
    /// default the in-flight basis resolves an unstated limit to.
    #[test]
    fn the_default_served_limits_are_the_unstated_requests() {
        let unstated = InFlightLimitBasis::PerCore {
            requests: nz(crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT),
        };
        assert_eq!(
            ServedLimits::default(),
            ServerLimits::default().served(unstated, nz(1))
        );
    }
}
