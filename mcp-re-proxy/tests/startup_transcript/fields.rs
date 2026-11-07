// SPDX-License-Identifier: Apache-2.0
//! Reading values out of one collapsed stderr line.
//!
//! Each `read_*` function owns one seam's wording: it extracts the state or value that
//! seam states, and refuses a state it does not recognize rather than guessing.

use super::event::StartupEvent;

/// One stderr line with its whitespace collapsed, so matching is about content and not
/// source layout.
pub(super) struct Line(String);

impl Line {
    pub(super) fn collapse(raw: &str) -> Self {
        Self(raw.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    pub(super) fn contains(&self, marker: &str) -> bool {
        self.0.contains(marker)
    }

    /// The remainder of the line after the first occurrence of `needle`.
    fn after(&self, needle: &str) -> Option<&str> {
        self.0.find(needle).map(|i| &self.0[i + needle.len()..])
    }

    /// The first whitespace-delimited word after `needle`.
    fn word_after(&self, needle: &str) -> Option<&str> {
        self.after(needle)?.split_whitespace().next()
    }

    /// The state `seam` states on this line: the value of the first `known` marker the
    /// line contains. A line stating none of them is a posture this harness does not know.
    fn state_of<T: Copy>(&self, seam: &str, known: &[(&str, T)]) -> T {
        match known.iter().find(|(marker, _)| self.contains(marker)) {
            Some((_, state)) => *state,
            None => self.unknown_state(seam),
        }
    }

/// A line that names a seam but whose STATE this harness does not recognize.
///
/// Unrecognized STATE is a hard failure, while an unrecognized LINE is dropped. The
/// asymmetry is the whole point, and it is not fussiness — it is the difference between
/// "I have nothing to say about this line" and "I am about to claim something I did not
/// observe".
///
/// `AdmissionCurrency` had the permissive shape and it was actively wrong: it matched
/// `"admission currency = "` and mapped anything that was not `REQUIRED` to `optional`. So
/// the moment production learned to announce the gate being OFF, this harness would have
/// reported *the admission-currency gate is running in optional mode* — a false ON,
/// produced silently, in the exact test whose job is to characterize what the deployment
/// enforces. A new posture state must never be able to enter a transcript as a weaker
/// existing one.
    fn unknown_state(&self, seam: &str) -> ! {
        let line = &self.0;
        panic!(
            "startup_transcript: the {seam} line states a posture this harness does not \
             recognize, so it cannot be characterized without guessing:\n  {line}\n\
             Add the new state to `normalize` — do NOT let it fall through to an existing \
             one, and do not drop it silently."
        );
    }
}

pub(super) fn read_revocation_tier(l: &Line) -> Option<StartupEvent> {
    Some(StartupEvent::RevocationTier {
        tier: l.word_after("revocation-tier=")?.to_string(),
        // "NONE:" means the store itself never changes while the process runs.
        store_change_bounded: !l.contains("store-change-cadence=NONE"),
    })
}

pub(super) fn read_replay_tier(l: &Line) -> StartupEvent {
    let backend = if l.contains("etcd") { "etcd" } else { "redis" };
    StartupEvent::ReplayTier {
        backend: backend.to_string(),
    }
}

pub(super) fn read_crl_loaded(l: &Line) -> StartupEvent {
    StartupEvent::CrlLoaded {
        files: l.word_after("enabled — ")
            .and_then(|w| w.parse().ok())
            .unwrap_or(0),
    }
}

pub(super) fn read_revocation_posture(l: &Line) -> StartupEvent {
    StartupEvent::RevocationPosture {
        mode: l.word_after("revocation_mode=")
            .unwrap_or("connection")
            .to_string(),
    }
}

pub(super) fn read_online_ocsp(l: &Line) -> StartupEvent {
    let known = [("revocation enabled", true), ("revocation = OFF", false)];
    StartupEvent::OnlineOcsp {
        enabled: l.state_of("ONLINE OCSP client-cert revocation", &known),
    }
}

pub(super) fn read_mcp_transport_contract(l: &Line) -> StartupEvent {
    StartupEvent::McpTransportContract {
        enforced: l.state_of("MCP transport contract", &[("contract ENFORCED", true)]),
    }
}

pub(super) fn read_freshness_gate(l: &Line) -> StartupEvent {
    StartupEvent::FreshnessGate {
        skew_secs: l.after("created-")
            .and_then(|r| r.split('s').next()?.parse().ok())
            .unwrap_or(0),
    }
}

pub(super) fn read_evidence_retention(l: &Line) -> StartupEvent {
    let known = [("evidence retention = ON", true), ("evidence retention = OFF", false)];
    StartupEvent::EvidenceRetention {
        enabled: l.state_of("evidence retention", &known),
    }
}

pub(super) fn read_verified_context_carrier(l: &Line) -> StartupEvent {
    let known = [("carrier = TRUSTED", true), ("carrier = OFF", false)];
    StartupEvent::VerifiedContextCarrier {
        trusted: l.state_of("verified-context carrier", &known),
    }
}

pub(super) fn read_admission_currency(l: &Line) -> StartupEvent {
    let known = [
        ("admission currency = OFF", "off"),
        ("admission currency = REQUIRED", "required"),
        ("admission currency = optional", "optional"),
    ];
    StartupEvent::AdmissionCurrency {
        enforcement: l.state_of("admission currency", &known).to_string(),
    }
}

pub(super) fn read_authorization(l: &Line) -> StartupEvent {
    let known = [
        ("authorization = PDP-DECISION enforced", true),
        ("authorization = OFF", false),
    ];
    StartupEvent::Authorization {
        enforced: l.state_of("authorization", &known),
    }
}

/// The security-audit line: the observer and the delivery, each read from its own words.
/// Anything else is a posture this harness does not know, and it says so.
pub(super) fn read_audit_posture(l: &Line) -> StartupEvent {
    let mode = if l.contains("record = STDERR, ") {
        "stderr"
    } else if l.contains("record = OFF (--audit-sink none), ") {
        "off"
    } else {
        l.unknown_state("security audit record");
    };
    let delivery = if l.contains("delivery = BEST-EFFORT") {
        "best-effort".to_string()
    } else if let Some(rest) = l.after("delivery = REQUIRED via provider ") {
        let tier = rest.split_once(", tier ").map(|(_, tier)| tier).and_then(|t| t.split(' ').next());
        match tier {
            Some(tier) if mode == "stderr" => format!("required:{tier}"),
            _ => l.unknown_state("security audit record"),
        }
    } else {
        l.unknown_state("security audit record");
    };
    StartupEvent::AuditSink {
        mode: mode.to_string(),
        delivery,
    }
}
