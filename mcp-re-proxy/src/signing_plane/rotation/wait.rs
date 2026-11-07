// SPDX-License-Identifier: Apache-2.0
//! What a rotation loop is bound to, and how it waits for its next window.

use std::sync::Arc;
use std::time::Duration;

use crate::clock::now_unix;

use crate::signing_plane::trust_epoch_advance::epoch_moved;
use crate::signing_plane::DelegatedEpochWatch;

/// What one rotation loop is bound to: the signer it keeps in force, the overlap it mints
/// within, the shared trust epoch it watches, and the halt that ends it.
pub(in crate::signing_plane) struct RotationScope<'a> {
    pub(in crate::signing_plane) signer:
        &'a Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    pub(in crate::signing_plane) overlap: i64,
    pub(in crate::signing_plane) epoch_watch: Option<&'a DelegatedEpochWatch>,
    pub(in crate::signing_plane) halt: &'a crate::managed_worker::Halt,
}

impl RotationScope<'_> {
    /// Whether the loop is over. A permanently retired signer ends the loop like a halt:
    /// nothing it mints is published, so every later attempt would only count a failure
    /// against a dead signer.
    pub(super) fn stopped(&self) -> bool {
        self.halt.requested() || self.signer.is_retired_permanently()
    }
}

/// Wait until the overlap window opens, or until the shared trust epoch moves.
///
/// In steady state the loop sleeps until `exp - overlap`, so a successor is minted while
/// the predecessor is still valid. The wait ALSO breaks early when the shared trust epoch
/// advances, which is what bounds cross-replica revocation by the ~500ms epoch poll rather
/// than by a full TTL. With no current key — startup edge, or post-retirement — it rotates
/// at once.
///
/// An unreadable epoch is not an advance: the wait keeps polling, and records a failure
/// once per wait when it first sees one so the metric stops reading healthy.
///
/// Returns `true` when a halt was requested.
pub(super) fn wait_for_window(
    scope: &RotationScope<'_>,
    last_epoch: &mcp_re_http_profile::custody::TrustEpoch,
) -> bool {
    let wake_at = window_opens_at(scope.signer, scope.overlap);
    let mut ticks = 0u32;
    let mut unreadable_seen = false;
    while now_unix() < wake_at {
        if scope.halt.requested() {
            return true;
        }
        // Poll the shared trust epoch ~every 500ms (10 * 50ms).
        let polling = ticks.is_multiple_of(10);
        if polling
            && scope.epoch_watch.is_some_and(|watch| {
                epoch_moved(scope.signer, watch, last_epoch, &mut unreadable_seen)
            })
        {
            break;
        }
        // Wrapping IS the algebra: a phase counter read only through `is_multiple_of(10)`
        // names a position in a cycle and has no largest value to overflow past.
        ticks = ticks.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The instant the overlap window opens, or now when there is no current key.
fn window_opens_at(
    signer: &crate::delegated_server_signer::DelegatedServerSigner,
    overlap: i64,
) -> i64 {
    match signer.current(now_unix()) {
        // Class R: a window start that cannot be computed wakes the worker NOW. Wrapping
        // parks this worker for the life of the process, so the key is never rotated.
        Some(a) => a
            .exp()
            .checked_sub(overlap)
            .unwrap_or(i64::MIN)
            .max(now_unix()),
        None => now_unix(),
    }
}
