//! The leases already granted, keyed by the instant they expire.
//!
//! A lease per admitted nonce makes the outstanding-lease count grow with REQUEST
//! VOLUME, and etcd's lessor carries every one of them until it expires. Keys that
//! stop being retained at the same second want the same expiry, so they can share
//! one lease: the count then grows with the FRESHNESS WINDOW instead — at most one
//! lease per second of `max_signature_validity + skew`, whatever the request rate.
//! Reaching etcd's backend quota raises a NOSPACE alarm that keeps the cluster
//! read-only until an operator compacts, defragments and disarms it, so the
//! difference is between a bounded working set and a sticky manual outage chosen
//! by one signature-valid peer.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// `retain_until` -> the lease already granted to expire at that instant.
pub(super) struct LeasePool {
    leases: Mutex<BTreeMap<i64, i64>>,
}

impl LeasePool {
    pub(super) fn new() -> Self {
        LeasePool {
            leases: Mutex::new(BTreeMap::new()),
        }
    }

    /// The lease already granted to expire at `retain_until`, if one is still live.
    ///
    /// Drops every lease whose instant has arrived first: etcd revokes those itself, and
    /// attaching a key to a lease that no longer exists leaves the key unretained — the
    /// direction that re-opens replay. The instant `now` counts as arrived, so the pool
    /// errs towards one extra grant rather than towards one unretained nonce. The map is
    /// bounded by the freshness window in seconds, not by request volume.
    pub(super) fn pooled(&self, retain_until: i64, now: i64) -> Option<i64> {
        // A poisoned pool is not a reason to fail a request closed: the worst outcome
        // of ignoring it is granting a lease that could have been shared.
        let mut leases = self.leases.lock().ok()?;
        *leases = leases.split_off(&now.saturating_add(1));
        leases.get(&retain_until).copied()
    }

    /// Offer a freshly granted lease for reuse by later nonces retained to the same
    /// instant. Best effort: a lease nobody reuses simply expires on its own TTL.
    pub(super) fn offer(&self, retain_until: i64, lease_id: i64) {
        if let Ok(mut leases) = self.leases.lock() {
            leases.insert(retain_until, lease_id);
        }
    }

    /// Stop offering `lease_id` for `retain_until` — it did not work, so no further
    /// request may be built on it.
    pub(super) fn forget(&self, retain_until: i64, lease_id: i64) {
        if let Ok(mut leases) = self.leases.lock() {
            if leases.get(&retain_until) == Some(&lease_id) {
                leases.remove(&retain_until);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.leases.lock().expect("pool").is_empty()
    }
}
