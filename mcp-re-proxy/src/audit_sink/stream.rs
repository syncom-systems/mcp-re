// SPDX-License-Identifier: Apache-2.0
//! The presentation of this process's stderr audit stream, and the acquisition of the run
//! identity it names.
//!
//! A `seq` alone numbers one run and starts again at 0 in the next one, so two runs' records
//! interleave numerically in a collector that keeps both. The position of a record is the
//! pair `(run, seq)` its event was produced with: `seq` is ordered only within its run, and
//! the run is what a reader partitions on. A run whose stream has a start line and no
//! terminal line ended with an unknown tail.

use std::sync::OnceLock;

use crate::audit_record::RunId;

/// Sixteen bytes from the OS CSPRNG, for a run identity. `None` when the CSPRNG fails, which
/// opens no run and refuses startup.
///
/// The one place the audit path asks the OS for entropy (`boundary.os_entropy`). What the
/// bytes MEAN — a run, numbered from 0 — is [`RunId`]'s.
pub(crate) fn draw_run_entropy() -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

/// The run this process's stderr stream was opened on, set once when it states its start.
pub(super) static STREAM: OnceLock<RunId> = OnceLock::new();

/// The run of this process's stream, or `None` when no stream was opened — in which case
/// nothing was ever recorded on it and there is nothing to speak of.
pub(super) fn opened_run() -> Option<RunId> {
    STREAM.get().copied()
}

/// ` run=<hex>` for a stream-level line, or nothing when no stream was opened in this
/// process.
pub(super) fn run_suffix() -> String {
    opened_run()
        .map(|run| format!(" run={run}"))
        .unwrap_or_default()
}

/// The line that opens a run's stream, before its first record.
pub(super) fn start_line(run: &RunId) -> String {
    format!("mcp-re-proxy: audit stream started run={run}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_lines_name_the_opened_run() {
        let run = crate::audit_record::open_process_run().expect("the OS CSPRNG yields a run");
        assert_eq!(
            start_line(&run),
            format!("mcp-re-proxy: audit stream started run={run}")
        );
        crate::audit_sink::StderrAuditSink::open().expect("the process run is open");
        assert_eq!(opened_run(), Some(run));
        assert_eq!(run_suffix(), format!(" run={run}"));
    }

    #[test]
    fn a_draw_yields_sixteen_bytes_and_two_draws_differ() {
        let (a, b) = (draw_run_entropy(), draw_run_entropy());
        assert!(a.is_some(), "the OS CSPRNG yields bytes");
        assert_ne!(a, b);
    }
}
