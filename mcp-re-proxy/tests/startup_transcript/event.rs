// SPDX-License-Identifier: Apache-2.0
//! The normalized vocabulary: events, outcomes and the transcript that holds them.

/// One normalized startup fact.
///
/// Deliberately LOSSY about anything unstable — bound ports, timestamps, temp paths,
/// generated ids, elapsed times — because none of those are the behaviour under test. A
/// value appears only where it is itself part of the claim (a declared tier, an
/// enforced mode, a configured bound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupEvent {
    /// Host clock reads at/near the Unix epoch; freshness will fail closed.
    ClockFaultWarning,
    /// The declared revocation tier, and whether the trust store itself can change.
    RevocationTier {
        tier: String,
        store_change_bounded: bool,
    },
    /// Push tier configured with no networked event source; running at its fallback.
    PushTierNoEventSource,
    /// Whether `--trust` is re-read on a cadence.
    TrustReload { active: bool },
    /// The authoritative replay tier that was opened.
    ReplayTier { backend: String },
    /// Offline client-cert revocation: how many CRL files were loaded.
    CrlLoaded { files: usize },
    /// A loaded CRL is near its `nextUpdate`.
    CrlNearExpiryWarning,
    /// The structured `mcp-re.revocation.posture` line and its declared mode.
    RevocationPosture { mode: String },
    /// Fleet-wide cross-replica revocation-lag bounds were computed.
    FleetLagBounds,
    /// TLS handshake key custody.
    TlsCustody { delegated: bool },
    /// In-process CRL hot-reload, and whether it was actually scheduled.
    CrlReload { scheduled: bool },
    /// Whether online OCSP client-cert revocation is consulted per handshake.
    OnlineOcsp { enabled: bool },
    /// The inner-plane in-flight bound was raised to match the fleet ceiling.
    InFlightCeilingRaised,
    /// The shared trust-epoch watch is active for delegated minting.
    DelegatedEpochWatch,
    /// Response signing is delegated and the first key has been issued.
    ResponseSigningDelegated,
    /// Whether the MCP transport/version contract is enforced.
    McpTransportContract { enforced: bool },
    /// The RFC 9421 freshness gate's configured skew, in seconds.
    FreshnessGate { skew_secs: u64 },
    /// Where the per-request security record goes — `stderr` or `off` — and how it is
    /// delivered: `best-effort`, or `required:<declared tier>`.
    AuditSink { mode: String, delivery: String },
    /// Whether accepted exchanges are retained.
    EvidenceRetention { enabled: bool },
    /// Whether the PEP writes its own verified context into the forwarded body.
    VerifiedContextCarrier { trusted: bool },
    /// Whether MRTR continuations are shared across replicas.
    ContinuationStore { shared: bool },
    /// The admission-currency gate's enforcement level — `required`, `optional`, or
    /// `off`.
    AdmissionCurrency { enforcement: String },
    /// Whether an authorization authority decides MAY-ACT for this deployment.
    Authorization { enforced: bool },
    /// The fleet bound its listener and is serving. Startup finished.
    FleetServing,
    /// The fleet drained cleanly after a stop signal.
    FleetDrained,
}

/// How a captured run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The process exited on its own. `refused` carries the final diagnostic line for a
    /// non-zero exit — the operator-visible reason startup was refused.
    Exited {
        success: bool,
        refused: Option<String>,
    },
    /// The proxy reached its serving state and was stopped by the harness.
    ServedThenStopped,
    /// Neither happened within the deadline.
    TimedOut,
}

/// One startup, as observed from outside the process.
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Normalized events in emission order.
    pub events: Vec<StartupEvent>,
    pub outcome: Outcome,
    /// Every stderr line, kept for diagnosing an assertion failure. Never asserted on.
    pub raw: Vec<String>,
}

impl Transcript {
    /// Whether `event` appears at all.
    pub fn has(&self, event: &StartupEvent) -> bool {
        self.events.contains(event)
    }

    /// The index of the first occurrence of `event`.
    pub fn position_of(&self, event: &StartupEvent) -> Option<usize> {
        self.events.iter().position(|e| e == event)
    }

    /// Whether `first` is emitted before `second`. Both must be present.
    ///
    /// Order is the property most at risk in a restructuring that moves phases into
    /// separate materializers, so it gets a first-class assertion rather than being
    /// spelled out at every call site.
    pub fn emits_in_order(&self, first: &StartupEvent, second: &StartupEvent) -> bool {
        match (self.position_of(first), self.position_of(second)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        }
    }

    /// The raw transcript, for an assertion message.
    pub fn dump(&self) -> String {
        self.raw.join("\n")
    }
}
