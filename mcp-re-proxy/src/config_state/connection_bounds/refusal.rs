// SPDX-License-Identifier: Apache-2.0
//! The three rules [`super::ConnectionBounds`] is resolved through, as refusals an operator
//! reads.
//!
//! Apart from the value because they answer a different question: the value says what a
//! connection is bounded by, these say why a request's limits bound nothing. Each keeps the
//! text it has always had, and [`super::ConnectionBounds::from_limits`] places them in the
//! order an operator reads them — the ceiling, the drain window, then the three timeouts.

use std::time::Duration;

use crate::deployment_request::ServerLimits;

/// The same one-day ceiling the parser puts on every timeout. `CoreAdmission::drain` declines
/// to wait at all when `Instant::now().checked_add(grace)` fails, so an unrepresentable window
/// abandons every in-flight request just as a zero one does.
const DRAIN_GRACE_CEILING: Duration = Duration::from_secs(86_400);

/// Whether a drain window shorter than the request deadline is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cover {
    /// A deployment: the window must cover the deadline.
    Required,
    /// A directly built `ServerOptions`: the grace bounds the drain on its own.
    NotRequired,
}

/// A limit of zero disables the control it bounds, which is a security posture whatever tier
/// it sits in.
pub(super) fn ceiling(limits: &ServerLimits) -> Vec<String> {
    if limits.max_concurrent_connections != 0 {
        return Vec::new();
    }
    vec![
        "--max-connections 0 accepts no connection at all: there is no \"unlimited\" \
          spelling, because an unbounded connection count is attacker-controlled \
          buffering ahead of the verify gate. Set a positive ceiling"
            .to_string(),
    ]
}

/// The drain window is positive and representable, and for a deployment it covers the request
/// deadline. A window of zero is the absence of the window.
pub(super) fn drain_window(limits: &ServerLimits, cover: Cover) -> Vec<String> {
    let grace = limits.drain_grace;
    if grace.is_zero() {
        return vec![
            "--drain-grace-secs 0 abandons every in-flight request on SIGTERM: the \
                     drain window is what lets an admitted request finish before the listener \
                     goes away, and the k8s invariant request_deadline <= drain_grace < \
                     terminationGracePeriodSeconds cannot hold with a zero window. Set a \
                     positive window (default 30s)"
                .to_string(),
        ];
    }
    let mut out = Vec::new();
    if grace > DRAIN_GRACE_CEILING {
        out.push(
            "--drain-grace-secs exceeds the 86400s ceiling: the drain deadline is not \
             representable, so the drain declines to wait and abandons every in-flight \
             request on SIGTERM. Set a window of at most 86400s"
                .to_string(),
        );
    }
    if cover == Cover::Required
        && limits
            .request_deadline
            .is_some_and(|deadline| grace < deadline)
    {
        out.push(
            "--drain-grace-secs is shorter than --request-deadline-secs: the k8s invariant \
             request_deadline <= drain_grace requires the window to cover the deadline, \
             otherwise a request the deadline still allows is abandoned on SIGTERM"
                .to_string(),
        );
    }
    out
}

/// The read, write and request-deadline timeouts are the slow-loris defense; a disabled one
/// removes it for every connection.
pub(super) fn slow_loris(limits: &ServerLimits) -> Vec<String> {
    [
        (limits.read_timeout, "--read-timeout-secs"),
        (limits.write_timeout, "--write-timeout-secs"),
        (limits.request_deadline, "--request-deadline-secs"),
    ]
    .into_iter()
    .filter(|(value, _)| value.is_none())
    .map(|(_, flag)| {
        format!(
            "{flag} 0 disables a slow-loris defense: a peer that trickles bytes then \
             holds a serve slot indefinitely, up to --max-connections, with no \
             fail-closed drop. Set a bounded value (default 30s)"
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legal_request_raises_no_refusal() {
        let limits = ServerLimits::default();
        assert!(ceiling(&limits).is_empty());
        assert!(drain_window(&limits, Cover::Required).is_empty());
        assert!(slow_loris(&limits).is_empty());
    }

    #[test]
    fn the_cover_rule_applies_only_where_it_is_required() {
        let limits = ServerLimits {
            request_deadline: Some(Duration::from_secs(60)),
            drain_grace: Duration::from_secs(30),
            ..ServerLimits::default()
        };
        assert_eq!(drain_window(&limits, Cover::Required).len(), 1);
        assert!(drain_window(&limits, Cover::NotRequired).is_empty());
    }
}
