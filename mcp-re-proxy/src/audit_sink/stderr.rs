// SPDX-License-Identifier: Apache-2.0
//! The stderr audit sink: a handle on this process's audit stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use super::stream;
use super::writer::{stderr_audit_writer, AuditMessage, STDERR_AUDIT_DROPPED, STDERR_AUDIT_QUEUED};
use super::{admission_ceiling, offer, AuditSink, STDERR_AUDIT_QUEUE_DEPTH};
use crate::audit_record::text::{render_record, AuditField};
use crate::audit_record::{AuditEnvelope, AuditRecord, EventId, EventIdentityFailure, RunId};

/// The default sink: one structured line per decision on stderr, the proxy's
/// diagnostic channel.
///
/// Deliberately plain text with stable `key=value` fields rather than JSON — the
/// startup lines and rotation warnings on this channel already use this shape, and a
/// deployment that wants structured audit ships its own [`AuditSink`].
///
/// The line is formatted on the request path and then HANDED OFF: a dedicated thread
/// owns stderr, so the trait's "MUST NOT block the request path" is a property of the
/// implementation rather than a hope about the writer. It matters because `record` is
/// reached from the preflight rejection path — before any signature verifies — so an
/// unauthenticated peer decides how often it is called. Writing inline meant a log
/// collector applying backpressure, a rotation, or a full volume stalled the serving
/// core inside the request future, and a closed stderr PANICKED the connection task.
/// Neither degrades to "audit lost, request served", which is the documented intent.
///
/// The hand-off queue is bounded and DROPS when full, which is the same intent from the
/// other side: audit must never fail or delay a request. Three things keep that from
/// becoming an attacker-chosen blind spot:
///
/// * **Every line carries its event's identity `seq=N run=<hex>`**, allocated when the
///   event was produced and so before the hand-off. `seq` is monotonic within one run of the
///   process, and `run` names the run. A dropped record is then a numbered hole in its run's
///   stream, so which decisions are missing is readable from the surviving records rather
///   than inferred from an aggregate.
/// * **An unattributed record cannot consume the whole queue.** The flood an
///   unauthenticated peer can produce is by construction unattributed — no actor was
///   resolved — so those records are admitted only while the queue is below
///   [`STDERR_AUDIT_UNATTRIBUTED_CEILING`](super::STDERR_AUDIT_UNATTRIBUTED_CEILING). The remaining depth is reachable only by a
///   record naming a verifier-resolved actor, which is what stops a preflight flood from
///   evicting the decisions an attacker wants unrecorded.
/// * **The drop count is reported on a timer**, not only by the next record. A burst that
///   ends in silence still says so.
///
/// What none of that changes: records still in the queue at process exit are lost unless
/// the shutdown path calls [`drain::at_shutdown`](super::drain::at_shutdown). A run that died that way has a start
/// line and no shutdown line.
#[derive(Debug, Clone, Copy)]
pub struct StderrAuditSink {
    run: RunId,
}

/// Whether this process's stream has already said that a decision could not be numbered.
static UNNUMBERED_STATED: AtomicBool = AtomicBool::new(false);

impl StderrAuditSink {
    /// The sink of this process's audit stream. The first call opens this process's run and
    /// writes the stream's start line; later calls return a sink on the same run. `None`
    /// when the OS CSPRNG fails, which refuses startup.
    pub fn open() -> Option<Self> {
        let run = crate::audit_record::open_process_run()?;
        Some(Self::open_on(
            run,
            &stream::STREAM,
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
        ))
    }

    /// [`Self::open`] on `run`, over a given stream cell and writer queue. The cell is set
    /// once, and only the call that sets it states the start.
    fn open_on(
        run: RunId,
        cell: &OnceLock<RunId>,
        queue: &std::sync::mpsc::SyncSender<AuditMessage>,
        dropped: &std::sync::atomic::AtomicU64,
        queued: &std::sync::atomic::AtomicUsize,
    ) -> Self {
        if cell.set(run).is_ok() {
            let line = stream::start_line(&run);
            offer(queue, dropped, queued, line, STDERR_AUDIT_QUEUE_DEPTH);
        }
        StderrAuditSink { run }
    }

    /// Say, once per process, that this run stopped numbering decisions.
    fn state_unnumbered(
        &self,
        failure: &EventIdentityFailure,
        stated: &AtomicBool,
        queue: &std::sync::mpsc::SyncSender<AuditMessage>,
        dropped: &std::sync::atomic::AtomicU64,
        queued: &std::sync::atomic::AtomicUsize,
    ) {
        if stated.swap(true, Ordering::Relaxed) {
            return;
        }
        let warning = format!(
            "mcp-re-proxy: WARNING: audit run={} cannot number a decision ({failure}); it and \
             every later decision this run cannot number are missing from the stream, and \
             this warning is not repeated",
            self.run
        );
        offer(queue, dropped, queued, warning, STDERR_AUDIT_QUEUE_DEPTH);
    }
}

impl AuditSink for StderrAuditSink {
    fn record(&self, envelope: &AuditEnvelope) {
        let line = audit_line(&envelope.id(), envelope.record());
        offer(
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
            line,
            admission_ceiling(envelope.record()),
        );
    }

    fn unnumbered(&self, failure: &EventIdentityFailure) {
        self.state_unnumbered(
            failure,
            &UNNUMBERED_STATED,
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
        );
    }
}

/// One record's line, under the identity its event was produced with.
///
/// The identity is the event's, not this sink's: it was allocated once when the event was
/// produced, so a line delivered again is the same `seq` in the same run. The sink
/// interprets nothing it was handed: a field slice carries no vocabulary, and
/// `render_record` owns every question of spelling.
fn audit_line(id: &EventId, record: &AuditRecord) -> String {
    let run = id.run();
    let seq = id.seq_within(&run).unwrap_or_default();
    let mut fields = vec![
        AuditField::number("seq", seq),
        AuditField::text("run", run.to_string()),
    ];
    fields.extend(record.audit_fields());
    format!("mcp-re-proxy: audit {}", render_record(&fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::AuditSubject;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;

    fn accepted(actor: &str) -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some(actor.into()),
            status: 200,
            at_unix: 10,
        }
    }

    /// A record's line names its position — its number AND the run that number belongs to —
    /// so a dropped one is a numbered hole in a named run rather than an aggregate nobody can
    /// attribute, and an equal number from another run of the process cannot stand in for it.
    #[test]
    fn every_line_names_its_run_and_its_number_in_that_run() {
        let sink = StderrAuditSink::open().expect("the OS CSPRNG yields a run");
        let collector = std::sync::Arc::new(crate::audit_sink::CollectingAuditSink::new());
        let accepted = accepted("actor-a");
        crate::audit_record::record_to(
            &Some(collector.clone()),
            None,
            accepted.subject,
            accepted.actor_id,
            200,
            10,
        );
        let envelope = collector.envelopes().pop().expect("the event was produced");
        let run = sink.run;
        assert_eq!(
            envelope.id().run(),
            run,
            "events are numbered in the run the stream names"
        );
        let seq = envelope
            .id()
            .seq_within(&run)
            .expect("the event's identity is in the stream's run");
        let line = audit_line(&envelope.id(), envelope.record());
        assert!(
            line.starts_with(&format!("mcp-re-proxy: audit seq={seq} run={run} ")),
            "{line}"
        );
    }

    /// The record line, byte for byte, as v0.18.1 wrote it: an accepted request, an
    /// unattributed request refused at admission with a Core reason, and a signed response,
    /// at the first three numbers of one run.
    #[test]
    fn a_record_line_is_byte_identical_to_v0_18_1() {
        let run = crate::audit_record::open_process_run().expect("the OS CSPRNG yields a run");
        let allocator = crate::audit_record::EventAllocator::starting_at(run, 0);
        let produce = |link, record| {
            AuditEnvelope::produce_for_test(&allocator, link, record).expect("produced")
        };
        let refused = AuditRecord {
            subject: AuditSubject::request_refused_at_admission(
                Some(&mcp_re_core::McpReError::ReplayDetected),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                crate::admission_enforcer::AdmissionRefusalClass::NoRecord,
            ),
            actor_id: None,
            status: 409,
            at_unix: 11,
        };
        let signed = AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some("actor-a".into()),
            status: 202,
            at_unix: 12,
        };
        let origin = produce(None, accepted("actor-a"));
        let envelopes = [
            produce(None, refused),
            produce(origin.exchange_coordinate(), signed),
        ];
        let lines =
            [&origin, &envelopes[0], &envelopes[1]].map(|e| audit_line(&e.id(), e.record()));
        assert_eq!(
            lines,
            [
                format!(
                    "mcp-re-proxy: audit seq=0 run={run} event=mcp-re.request.accepted \
                     decision=Accepted reason=- actor=actor-a status=200 at=10 \
                     authz=not-configured admission=not-configured"
                ),
                format!(
                    "mcp-re-proxy: audit seq=1 run={run} event=mcp-re.request.rejected \
                     decision=Rejected reason=mcp-re.replay_detected actor=- status=409 at=11 \
                     authz=refused-before-policy admission=refused admission_refusal=no-record"
                ),
                format!(
                    "mcp-re-proxy: audit seq=2 run={run} event=mcp-re.response.signed \
                     decision=Signed reason=- actor=actor-a status=202 at=12"
                ),
            ]
        );
    }

    /// A run's stream states its start exactly once, naming the run its records carry, so a
    /// run with a start and no shutdown line is one whose tail is unknown.
    #[test]
    fn a_stream_states_its_start_once_naming_its_run() {
        let cell = OnceLock::new();
        let (queue, lines) = std::sync::mpsc::sync_channel(4);
        let (dropped, queued) = Default::default();
        let run = crate::audit_record::open_process_run().expect("the OS CSPRNG yields a run");
        let open = || StderrAuditSink::open_on(run, &cell, &queue, &dropped, &queued);
        let sink = open();
        let again = open();
        assert_eq!(again.run, sink.run, "one stream, one run");
        let offered: Vec<String> = lines
            .try_iter()
            .map(|message| match message {
                AuditMessage::Line(line) => line,
                AuditMessage::Flush(_) => panic!("opening a stream flushes nothing"),
            })
            .collect();
        assert_eq!(
            offered,
            [format!("mcp-re-proxy: audit stream started run={run}")]
        );
    }

    /// Records handed to the sink are drainable at shutdown rather than lost with the
    /// detached writer.
    #[test]
    fn recorded_lines_are_drainable_at_shutdown() {
        let sink = StderrAuditSink::open().expect("the OS CSPRNG yields a run");
        let audit: crate::audit_sink::MaybeAuditSink = Some(std::sync::Arc::new(sink));
        let accepted = accepted("actor-a");
        crate::audit_record::record_to(&audit, None, accepted.subject, accepted.actor_id, 200, 10);
        crate::audit_record::record_to(
            &audit,
            None,
            AuditSubject::request_rejected(
                Some(&mcp_re_core::McpReError::ReplayDetected),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                AdmissionFacet::NotConfigured,
            ),
            None,
            403,
            11,
        );
        assert_eq!(
            super::super::drain::flush_for_test(std::time::Duration::from_secs(5)),
            super::super::drain::AuditDrain::Drained,
            "a queued record must be drainable at shutdown rather than lost with the \
             detached writer"
        );
    }

    /// A run that can number no more decisions says so — once, naming the run and why —
    /// rather than going quiet in a way that reads exactly like no traffic.
    #[test]
    fn an_exhausted_run_says_so_once() {
        let run = RunId::fixed([0xab; 16]);
        let exhausted = crate::audit_record::EventAllocator::starting_at(run, i64::MAX);
        let failure = AuditEnvelope::produce_for_test(&exhausted, None, accepted("actor-a"))
            .expect_err("an exhausted run numbers nothing");
        let (queue, lines) = std::sync::mpsc::sync_channel(4);
        let (dropped, queued) = Default::default();
        let stated = AtomicBool::new(false);
        let sink = StderrAuditSink { run };
        for _ in 0..3 {
            sink.state_unnumbered(&failure, &stated, &queue, &dropped, &queued);
        }
        let offered: Vec<String> = lines
            .try_iter()
            .map(|message| match message {
                AuditMessage::Line(line) => line,
                AuditMessage::Flush(_) => panic!("stating a failure flushes nothing"),
            })
            .collect();
        assert_eq!(
            offered,
            [
                "mcp-re-proxy: WARNING: audit run=abababababababababababababababab cannot number \
              a decision (the sequence of run abababababababababababababababab is exhausted); \
              it and every later decision this run cannot number are missing from the stream, \
              and this warning is not repeated"
            ]
        );
    }
}
