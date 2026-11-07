// SPDX-License-Identifier: Apache-2.0
//! An ORDERED, NORMALIZED view of what the proxy reports while it starts up.
//!
//! ADR-MCPRE-056 restructures the composition root. To show that restructuring preserved
//! behaviour, the tests need something to compare — and today the only things `app::run`
//! makes observable are its `Result` and 35 `eprintln!` posture statements. Snapshotting
//! that prose would be self-defeating: the same ADR (§11) then moves those statements
//! into structured records and explicitly permits the wording to change.
//!
//! So this harness reads the real binary's stderr and normalizes it into
//! [`StartupEvent`]s. Tests assert on the events and their ORDER, never on the text.
//! Startup order carries meaning — trust is resolved before the replay tier is opened,
//! and a posture line that moved across that boundary would be a real change — so this
//! is a `Vec`, not a set, and duplicates are preserved.
//!
//! **The marker strings here are a test synchronization dependency, not a logging
//! contract.** They are recognized because they are today's observable behaviour. Once
//! the refactor produces structured decision/evidence records, tests move to those and
//! this normalization layer is deleted.
//!
//! **Observed from outside.** The harness spawns the shipped binary rather than calling
//! `app::run` in-process, so it witnesses the system across the restructuring without
//! being coupled to any internal seam the restructuring introduces.


#![allow(dead_code)] // each test binary uses a subset

mod capture;
mod classify;
mod event;
mod fields;

pub use capture::capture;
pub use event::Outcome;
pub use event::StartupEvent;

/// Tests for the normalizer itself, which need no subprocess.
///
/// Worth having on their own terms — the harness is the instrument every characterization
/// assertion is read through, and an instrument that silently mis-reports is worse than a
/// missing one. They also happen to be the only coverage of `normalize` that runs when
/// spawning the proxy is unavailable.
#[cfg(test)]
mod normalize_tests {
    use super::classify::normalize;
    use super::StartupEvent;

    fn ev(line: &str) -> Option<StartupEvent> {
        normalize(&format!("mcp-re-proxy: {line}"))
    }

    /// Each seam is observable in BOTH directions, which is the property step 13 added to
    /// production and this harness exists to read back.
    #[test]
    fn every_state_carrying_seam_is_read_in_both_directions() {
        let cases: Vec<(&str, StartupEvent)> = vec![
            (
                "ONLINE OCSP client-cert revocation enabled (SHA-256 CertIDs)",
                StartupEvent::OnlineOcsp { enabled: true },
            ),
            (
                "ONLINE OCSP client-cert revocation = OFF: no responder is consulted",
                StartupEvent::OnlineOcsp { enabled: false },
            ),
            (
                "MCP transport contract ENFORCED for protocol version(s) [\"2026-07-28\"]",
                StartupEvent::McpTransportContract { enforced: true },
            ),
            (
                "verified-context carrier = TRUSTED (#415 §10)",
                StartupEvent::VerifiedContextCarrier { trusted: true },
            ),
            (
                "verified-context carrier = OFF (#415 §10)",
                StartupEvent::VerifiedContextCarrier { trusted: false },
            ),
            (
                "evidence retention = ON at /tmp/x (ADR-MCPRE-054)",
                StartupEvent::EvidenceRetention { enabled: true },
            ),
            (
                "evidence retention = OFF: nothing is retained",
                StartupEvent::EvidenceRetention { enabled: false },
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(ev(line), Some(expected), "misread: {line}");
        }
    }

    /// The three admission states are distinguished, including the one that used to be
    /// unreachable. `off` must NOT arrive as `optional`.
    #[test]
    fn admission_currency_never_reads_off_as_a_running_mode() {
        let off = ev(
            "admission currency = OFF (--admission off): a call carrying a fresh \
                      assertion is served even after its workload has been revoked",
        );
        assert_eq!(
            off,
            Some(StartupEvent::AdmissionCurrency {
                enforcement: "off".to_string()
            }),
            "an OFF gate must never be reported as a running enforcement mode"
        );
        assert_eq!(
            ev("admission currency = REQUIRED (authority k1, shared record over redis)"),
            Some(StartupEvent::AdmissionCurrency {
                enforcement: "required".to_string()
            })
        );
        assert_eq!(
            ev("admission currency = optional (authority k1, shared record over redis)"),
            Some(StartupEvent::AdmissionCurrency {
                enforcement: "optional".to_string()
            })
        );
    }

    /// A line carrying no startup fact is DROPPED. The proxy also writes per-request audit
    /// records and operational diagnostics to this channel, and a harness that failed on
    /// each of them would be unusable.
    #[test]
    fn a_line_that_states_no_seam_is_dropped_not_failed() {
        assert_eq!(normalize("mcp-re-proxy: some unrelated diagnostic"), None);
        assert_eq!(normalize(""), None);
    }

    /// A line that names a seam but states an UNKNOWN posture fails loudly. This is the
    /// asymmetry: silence about a line is fine, guessing about a state is not.
    #[test]
    #[should_panic(expected = "states a posture this harness does not recognize")]
    fn an_unrecognized_admission_state_fails_rather_than_guessing() {
        ev("admission currency = ADVISORY (authority k1)");
    }

    /// The same rule for a seam whose two states are spelled quite differently, to show it
    /// is the rule and not one lucky matcher.
    #[test]
    #[should_panic(expected = "states a posture this harness does not recognize")]
    fn an_unrecognized_audit_sink_state_fails_rather_than_guessing() {
        ev("security audit record = SYSLOG (ADR-MCPS-035)");
    }

    /// A delivery this harness does not know fails rather than reading as best-effort.
    #[test]
    #[should_panic(expected = "states a posture this harness does not recognize")]
    fn an_unrecognized_audit_delivery_fails_rather_than_guessing() {
        ev("security audit record = STDERR, delivery = EVENTUAL (ADR-MCPRE-070)");
    }

    /// Every audit posture production states is read, the OFF line included — it used to
    /// panic the harness, because the matcher looked for a `NONE` production never wrote.
    #[test]
    fn every_audit_posture_production_states_is_read() {
        let event = |mode: &str, delivery: &str| {
            Some(StartupEvent::AuditSink {
                mode: mode.into(),
                delivery: delivery.into(),
            })
        };
        assert_eq!(
            ev("security audit record = STDERR, delivery = BEST-EFFORT (ADR-MCPS-035): ..."),
            event("stderr", "best-effort")
        );
        assert_eq!(
            ev("security audit record = OFF (--audit-sink none), delivery = BEST-EFFORT: ..."),
            event("off", "best-effort")
        );
        assert_eq!(
            ev(
                "security audit record = STDERR, delivery = REQUIRED via provider journal, \
                tier SURVIVES_PROXY_PROCESS_LOSS (audit-durability/v1) as DECLARED ..."
            ),
            event("stderr", "required:SURVIVES_PROXY_PROCESS_LOSS")
        );
    }
}
