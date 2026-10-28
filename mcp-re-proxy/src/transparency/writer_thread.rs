// SPDX-License-Identifier: Apache-2.0
//! The dedicated retention writer thread, the channel into it, and how teardown reclaims it.
//!
//! One fact: the thread's lifetime. [`super::durable_writer`] is what runs on it, and
//! [`super::retention_queue`] decides which jobs may be handed to it; this owner starts it,
//! carries the one sender this side holds, and bounds how long a dropped store waits for it.

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;

use crate::retained_evidence::FsRetainedEvidenceStore;

use super::durable_job::WriteJob;
use super::durable_writer::write_loop;

/// The writer thread and the sender into its queue.
pub(super) struct WriterThread {
    /// Hand-off to the writer thread.
    jobs: SyncSender<WriteJob>,
    /// Reclaimed on drop within a bounded budget, so a dropped store has no writes still
    /// in flight — or says which ones it gave up waiting for.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for WriterThread {
    /// Close this side's sender, then reclaim the writer WITHIN A BUDGET.
    ///
    /// Dropping the last sender ends the writer's receive loop — but this is not the last
    /// sender. `reserve` hands every [`super::ReservedBeforeDispatch`] a clone, and that clone
    /// is not held through this type, so the store can reach its own `Drop` while a
    /// reservation is still alive on a task parked against a slow backend. The channel then
    /// never closes, `recv()` blocks forever, and an unbounded `join()` never returns: the
    /// whole shutdown deadlocks on a reservation that is itself waiting.
    ///
    /// So the wait is bounded, the same way `WorkerSet` bounds its own and for the same
    /// reason: a teardown that can hang is a teardown that has no deadline, and correctness
    /// on this path must not depend on every other holder having finished first. Past the
    /// budget the handle is dropped and the thread is left running, which is stated in the
    /// line below rather than left to be inferred from a process that never exits.
    ///
    /// Giving up the wait is not giving up the guarantee: nothing was acknowledged that is
    /// not durable, because acknowledgement happens after the fsync. What is lost is only
    /// the assurance that the queue was empty at the moment this type went away.
    fn drop(&mut self) {
        let (dead, _) = std::sync::mpsc::sync_channel(1);
        let live = std::mem::replace(&mut self.jobs, dead);
        drop(live);
        let Some(writer) = self.handle.take() else {
            return;
        };
        let now = std::time::Instant::now();
        // Class R: this budget bounds how long shutdown may wait, so a deadline that cannot
        // be represented is treated as already reached.
        let deadline = now
            .checked_add(crate::managed_worker::JOIN_DEADLINE)
            .unwrap_or(now);
        while !writer.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(WRITER_JOIN_POLL);
        }
        if writer.is_finished() {
            let _ = writer.join();
            return;
        }
        // RELINQUISHED. Written out because it is the one decision here that gives up a
        // guarantee, and should read as a choice rather than as a binding falling out of
        // scope.
        drop(writer);
        eprintln!(
            "mcp-re-proxy: the retained-evidence writer did not finish within {}s of its \
             store closing — a reservation still holds the queue open. It is left running \
             rather than blocking shutdown on it; nothing unacknowledged was durable, so no \
             completed exchange is in doubt.",
            crate::managed_worker::JOIN_DEADLINE.as_secs()
        );
    }
}

/// How often the drop path re-checks the writer while waiting out its budget.
const WRITER_JOIN_POLL: std::time::Duration = std::time::Duration::from_millis(10);

impl WriterThread {
    /// Start the writer thread over `store`, behind a queue of `capacity` jobs.
    pub(super) fn spawn(store: FsRetainedEvidenceStore, capacity: usize) -> std::io::Result<Self> {
        let (jobs, receiver) = std::sync::mpsc::sync_channel(capacity);
        let handle = std::thread::Builder::new()
            .name("mcp-re-retention".to_owned())
            .spawn(move || write_loop(store, receiver))?;
        Ok(WriterThread {
            jobs,
            handle: Some(handle),
        })
    }

    /// Queue `job` without waiting: a full queue and a stopped writer come back as they are.
    pub(super) fn try_send(&self, job: WriteJob) -> Result<(), TrySendError<WriteJob>> {
        self.jobs.try_send(job)
    }

    /// Another sender into the queue, for a job nobody awaits.
    pub(super) fn sender(&self) -> SyncSender<WriteJob> {
        self.jobs.clone()
    }
}

#[cfg(test)]
impl WriterThread {
    /// Put this side in the state a returned or panicked write loop leaves it: holding a
    /// sender whose receiver is gone.
    ///
    /// `#[cfg(test)]`, so it is not a production surface. It exists because the terminal
    /// fault is otherwise reachable only by making the writer thread panic, and a test that
    /// panicked a thread to reach it would be measuring the panic rather than the answer.
    pub(super) fn retire_for_test(&mut self) {
        let (orphaned, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        self.jobs = orphaned;
    }

    /// Put this side in the state a writer that drops every job unanswered leaves it: the
    /// queue accepts, and no acknowledgement ever comes back.
    pub(super) fn swallow_jobs_for_test(&mut self) {
        let (swallowing, receiver) = std::sync::mpsc::sync_channel(8);
        std::thread::spawn(move || while receiver.recv().is_ok() {});
        self.jobs = swallowing;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store(name: &str) -> (TempDir, FsRetainedEvidenceStore) {
        let path = std::env::temp_dir().join(format!(
            "mcp-re-writer-thread-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let store = FsRetainedEvidenceStore::open(&path).expect("open");
        (TempDir(path), store)
    }

    /// With no other sender alive, closing this side ends the writer's loop and the drop
    /// reclaims the thread, well inside the budget it would give up at.
    #[test]
    fn a_writer_with_no_other_sender_is_reclaimed_inside_the_budget() {
        let (_dir, store) = store("reclaimed");
        let thread = WriterThread::spawn(store, 4).expect("spawn");
        let started = std::time::Instant::now();
        drop(thread);
        assert!(started.elapsed() < crate::managed_worker::JOIN_DEADLINE);
    }

    /// A retired writer refuses every job as disconnected, never as a full queue.
    #[test]
    fn a_retired_writer_refuses_as_disconnected() {
        let (_dir, store) = store("retired");
        let mut thread = WriterThread::spawn(store, 4).expect("spawn");
        thread.retire_for_test();
        let (ack, _acked) = tokio::sync::oneshot::channel();
        let job = WriteJob::cleanup(
            super::super::durable_job::JobKind::Publish {
                path: std::path::PathBuf::from("unused"),
                bytes: Vec::new(),
                clear_marker: None,
            },
            ack,
        );
        assert!(matches!(
            thread.try_send(job),
            Err(TrySendError::Disconnected(_))
        ));
    }
}
