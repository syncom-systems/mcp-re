// SPDX-License-Identifier: Apache-2.0
//! Admission to the retention writer's queue, and the acknowledged hand-off of a job to it.
//!
//! One fact — whether a job may reach the writer, and what a failed hand-off was — and a
//! different one from [`super::durability`]'s. That one decides WHEN an exchange owes the
//! store a write and what each stage's failure means. [`super::writer_thread`] owns the
//! thread the jobs go to and how long teardown waits for it.
//!
//! The queue is bounded by the reservations, not the other way round: every security-bearing
//! job holds the [`AdmissionPermit`] it was admitted against, and
//! [`super::durability_bounds::write_queue_capacity`] sizes the queue from the reservation
//! ceiling. Admission is therefore one method here, so every job that can reach the writer
//! is counted by the same permit.

use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use crate::retained_evidence::FsRetainedEvidenceStore;

use super::durability_bounds::write_queue_capacity;
use super::durable_job::AdmissionPermit;
use super::durable_job::JobFault;
use super::durable_job::JobKind;
use super::durable_job::WriteJob;
use super::writer_thread::WriterThread;
use super::RetentionError;

/// The permits that bound the writer's queue, and the thread the queue feeds.
pub(super) struct RetentionQueue {
    /// Bounds concurrent reservations, and through them the queue.
    permits: Arc<tokio::sync::Semaphore>,
    /// The writer, and the sender into its queue.
    writer: WriterThread,
}

/// A writer that stopped before acknowledging: a pre-dispatch write is then unresolved.
fn writer_lost(pre_dispatch: bool) -> RetentionError {
    let lost = std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "retention writer stopped before acknowledging the write",
    );
    if pre_dispatch {
        RetentionError::Unresolved(lost)
    } else {
        RetentionError::Store(lost)
    }
}

impl RetentionQueue {
    /// Start the writer thread over `store`, with a queue sized for `max_reservations`.
    pub(super) fn start(
        store: FsRetainedEvidenceStore,
        max_reservations: usize,
    ) -> std::io::Result<Self> {
        let writer = WriterThread::spawn(store, write_queue_capacity(max_reservations))?;
        Ok(RetentionQueue {
            permits: Arc::new(tokio::sync::Semaphore::new(max_reservations)),
            writer,
        })
    }

    /// Admit one obligation to the queue, or refuse it.
    ///
    /// Taken BEFORE dispatch for every job the obligation will submit, so a full queue is an
    /// `ABORTED_BEFORE_EXECUTION` refusal — 503, backend untouched, retry safe — and never a
    /// completion the writer had no room for.
    pub(super) fn admit(&self) -> Result<Arc<AdmissionPermit>, RetentionError> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().map_err(|_| {
            RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retention queue is full",
            ))
        })?;
        Ok(Arc::new(permit))
    }

    /// A sender for the rescind a reservation queues as it goes out of scope.
    pub(super) fn rescind_sender(&self) -> SyncSender<WriteJob> {
        self.writer.sender()
    }

    /// Hand the writer a security-bearing job and await its acknowledgement.
    ///
    /// The `await` is the point of the whole arrangement: the runtime worker is free
    /// while the fsync runs. Every failure mode — a full queue, a dead writer, a dropped
    /// acknowledgement — is a failure, never a silent success. A dropped acknowledgement
    /// for a pre-dispatch job is unresolved: the store's state is unknown.
    ///
    /// `slot` is the permit this call was admitted against, and the job holds it too. The
    /// caller's future can be dropped at the `await` — hyper does exactly that when a
    /// connection goes — and the job it already queued does not leave with it. Without the
    /// job holding the slot, a cancelled call would hand its permit straight back and its
    /// orphaned job would still be in the queue, so the reservation ceiling would stop
    /// bounding the queue at all.
    pub(super) async fn submit(
        &self,
        kind: JobKind,
        slot: Arc<AdmissionPermit>,
    ) -> Result<(), RetentionError> {
        let pre_dispatch = kind.is_pre_dispatch();
        let (ack, acked) = tokio::sync::oneshot::channel();
        // `Full` and `Disconnected` are two facts and they demand two answers. A full queue
        // is genuine backpressure and an ordinary retry is correct — the capacity argument
        // in `durability_bounds` depends on it staying retryable. A disconnected one means
        // the writer thread has returned or panicked and NO future job will ever be
        // accepted, so answering it as transient tells a client to retry something that
        // cannot succeed until this replica is restarted.
        self.writer
            .try_send(WriteJob::accounted(kind, ack, slot))
            .map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => RetentionError::Store(
                    std::io::Error::new(std::io::ErrorKind::WouldBlock, "retention queue is full"),
                ),
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    RetentionError::StoreRetired(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "the retained-evidence writer has stopped; no further write will be \
                         accepted by this replica",
                    ))
                }
            })?;
        match acked.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(JobFault::NotPublished(e))) => Err(RetentionError::Store(e)),
            Ok(Err(JobFault::Unwithdrawn(e))) => Err(RetentionError::Unresolved(e)),
            Err(_) => Err(writer_lost(pre_dispatch)),
        }
    }
}

#[cfg(test)]
impl RetentionQueue {
    /// See [`WriterThread::retire_for_test`].
    pub(super) fn retire_writer_for_test(&mut self) {
        self.writer.retire_for_test();
    }

    /// See [`WriterThread::swallow_jobs_for_test`].
    pub(super) fn swallow_jobs_for_test(&mut self) {
        self.writer.swallow_jobs_for_test();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mcp-re-retention-queue-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn queue(name: &str, max_reservations: usize) -> (TempDir, RetentionQueue) {
        let dir = TempDir::new(name);
        let store = FsRetainedEvidenceStore::open(&dir.0).expect("open");
        let queue = RetentionQueue::start(store, max_reservations).expect("start");
        (dir, queue)
    }

    #[test]
    fn admission_stops_at_the_ceiling_and_a_returned_slot_admits_again() {
        let (_dir, queue) = queue("ceiling", 2);
        let first = queue.admit().expect("first slot");
        let _second = queue.admit().expect("second slot");
        assert!(matches!(queue.admit(), Err(RetentionError::Store(_))));
        drop(first);
        assert!(queue.admit().is_ok());
    }

    #[tokio::test]
    async fn a_retired_writer_is_a_retired_store_and_not_backpressure() {
        let (_dir, mut queue) = queue("retired", 2);
        queue.retire_writer_for_test();
        let slot = queue.admit().expect("slot");
        let job = JobKind::Publish {
            path: std::path::PathBuf::from("unused"),
            bytes: Vec::new(),
            clear_marker: None,
        };
        assert!(matches!(
            queue.submit(job, slot).await,
            Err(RetentionError::StoreRetired(_))
        ));
    }
}
