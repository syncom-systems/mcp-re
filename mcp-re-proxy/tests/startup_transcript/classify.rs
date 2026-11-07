// SPDX-License-Identifier: Apache-2.0
//! Mapping one stderr line to a [`StartupEvent`].
//!
//! The rules are an ordered table: the first rule whose markers all appear on the line
//! decides it, so a more specific rule must precede a broader one.

use super::event::StartupEvent;
use super::fields;
use super::fields::Line;

/// One recognizable startup statement: the markers that must all appear on the line, and
/// how to read the event out of it.
struct Rule {
    all: &'static [&'static str],
    read: fn(&Line) -> Option<StartupEvent>,
}

const RULES: &[Rule] = &[
    Rule {
        all: &["the system clock reads at/near the Unix epoch"],
        read: |_| Some(StartupEvent::ClockFaultWarning),
    },
    Rule {
        all: &["revocation-tier="],
        read: fields::read_revocation_tier,
    },
    Rule {
        all: &["revocation-tier PUSH has no networked event source"],
        read: |_| Some(StartupEvent::PushTierNoEventSource),
    },
    Rule {
        all: &["trust store reload ACTIVE"],
        read: |_| Some(StartupEvent::TrustReload { active: true }),
    },
    Rule {
        all: &["trust store reload OFF"],
        read: |_| Some(StartupEvent::TrustReload { active: false }),
    },
    Rule {
        all: &["replay tier = shared"],
        read: |l| Some(fields::read_replay_tier(l)),
    },
    Rule {
        all: &["offline client-cert revocation enabled"],
        read: |l| Some(fields::read_crl_loaded(l)),
    },
    Rule {
        all: &["is near expiry"],
        read: |_| Some(StartupEvent::CrlNearExpiryWarning),
    },
    Rule {
        all: &["mcp-re.revocation.posture"],
        read: |l| Some(fields::read_revocation_posture(l)),
    },
    Rule {
        all: &["cross-replica revocation-lag bounds"],
        read: |_| Some(StartupEvent::FleetLagBounds),
    },
    Rule {
        all: &["TLS custody = DELEGATED"],
        read: |_| Some(StartupEvent::TlsCustody { delegated: true }),
    },
    Rule {
        all: &["in-process CRL hot-reload enabled"],
        read: |_| Some(StartupEvent::CrlReload { scheduled: true }),
    },
    Rule {
        all: &["no --client-crl configured; no CRL reload scheduled"],
        read: |_| Some(StartupEvent::CrlReload { scheduled: false }),
    },
    Rule {
        all: &["ONLINE OCSP client-cert revocation"],
        read: |l| Some(fields::read_online_ocsp(l)),
    },
    Rule {
        all: &["inner-plane in-flight bound raised"],
        read: |_| Some(StartupEvent::InFlightCeilingRaised),
    },
    Rule {
        all: &["delegated trust-epoch watch ACTIVE"],
        read: |_| Some(StartupEvent::DelegatedEpochWatch),
    },
    Rule {
        all: &["response signing = DELEGATED"],
        read: |_| Some(StartupEvent::ResponseSigningDelegated),
    },
    Rule {
        all: &["MCP transport contract"],
        read: |l| Some(fields::read_mcp_transport_contract(l)),
    },
    Rule {
        all: &["freshness gate = created-"],
        read: |l| Some(fields::read_freshness_gate(l)),
    },
    Rule {
        all: &["security audit record = "],
        read: |l| Some(fields::read_audit_posture(l)),
    },
    Rule {
        all: &["evidence retention = "],
        read: |l| Some(fields::read_evidence_retention(l)),
    },
    Rule {
        all: &["verified-context carrier = "],
        read: |l| Some(fields::read_verified_context_carrier(l)),
    },
    Rule {
        all: &["MRTR continuation store = shared"],
        read: |_| Some(StartupEvent::ContinuationStore { shared: true }),
    },
    Rule {
        all: &["MRTR continuation", "OFF"],
        read: |_| Some(StartupEvent::ContinuationStore { shared: false }),
    },
    Rule {
        all: &["admission currency = "],
        read: |l| Some(fields::read_admission_currency(l)),
    },
    Rule {
        all: &["authorization = "],
        read: |l| Some(fields::read_authorization(l)),
    },
    Rule {
        all: &["async fleet serving on"],
        read: |_| Some(StartupEvent::FleetServing),
    },
    Rule {
        all: &["async fleet drained, exiting cleanly"],
        read: |_| Some(StartupEvent::FleetDrained),
    },
];

/// Map one stderr line to a normalized event, or `None` if it carries no startup fact.
///
/// Unknown lines are dropped rather than failing: the proxy also emits per-request audit
/// records and operational diagnostics on this channel, and a characterization harness
/// that broke whenever an unrelated line appeared would be worse than useless.
pub(super) fn normalize(line: &str) -> Option<StartupEvent> {
    // The source wraps these strings across source lines, which leaves runs of spaces in
    // the output. Collapse first so the matching below is about content, not layout.
    let line = Line::collapse(line);
    let rule = RULES
        .iter()
        .find(|rule| rule.all.iter().all(|marker| line.contains(marker)))?;
    (rule.read)(&line)
}
