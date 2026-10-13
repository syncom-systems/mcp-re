// SPDX-License-Identifier: Apache-2.0
//! Wall-clock acquisition for the proxy — the one place the OS clock enters.
//!
//! Reading the host clock is an authority, not a composition step: the value it
//! returns is trusted, and no proof in this codebase covers whether it is right. It
//! therefore has an owner of its own rather than living beside the code that wires the
//! runtime together, so that the modules needing the current time depend on a clock
//! rather than on a composition root.
//!
//! This module is named by `boundary.clock` in
//! `verification/policy/trust-boundaries.toml`. Keeping it small is the point: the
//! declared boundary is exactly as wide as the code that exercises the authority.
//!
//! Time is read here and passed DOWN as a value. Callers that receive a `now: i64`
//! parameter are consumers, not acquirers, and must not reach back here to re-read it
//! mid-decision — two readings inside one decision are two different instants.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The current time as whole Unix seconds (UTC).
///
/// A clock reading before the Unix epoch is clamped to `0` rather than reported as an
/// error, and that clamp is load-bearing in two opposite directions:
///
/// * For per-request freshness the clamp fails CLOSED. Every signature then fails its
///   freshness check instead of a stale one being admitted.
/// * For a boot-time refusal it does NOT. A comparison against a clock reading zero
///   declares every client CRL fresh, which is why [`reading_is_faulted`] treats `0` as
///   the sentinel for a broken host clock and startup refuses rather than warns when the
///   reading is the reference time for such a check.
///
/// A caller that needs one instant across several comparisons reads once and passes the
/// value, rather than calling this repeatedly.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A wall-clock reading below this Unix-seconds threshold is a host-clock fault:
/// 2000-01-01 UTC, far below any plausible deployment time, so a legitimate clock never
/// trips it while a 0/epoch clock always does.
pub(crate) const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// Whether `now_unix` says the host clock is unset or broken rather than merely
/// inaccurate (audit #94 F5).
///
/// Deciding that a reading is a FAULT is this owner's rule: the caller cannot conjure a
/// broken host clock to exercise it. [`now_unix`] clamps a pre-epoch `SystemTime` error to
/// 0, so 0 is the sentinel this catches, and any negative value is a fault by the same
/// argument.
pub(crate) fn reading_is_faulted(now_unix: i64) -> bool {
    now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS
}

/// The proxy's one startup reading of the host clock, taken once and classified once.
///
/// Every startup consumer of the boot instant receives this value rather than a raw
/// `i64`, so the planes and the fault diagnosis agree on one instant by construction —
/// not because the composition root read the clock once and remembered to pass the same
/// number on. The CRL freshness reference is projected from it by
/// [`crate::tls_plane::CrlReference::of`], which refuses a faulted reading where the fault
/// would disable the boot-time stale-CRL refusal.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StartupReading {
    unix: i64,
}

impl StartupReading {
    /// Read the host clock for startup.
    pub(crate) fn read() -> Self {
        Self { unix: now_unix() }
    }

    /// A reading at a chosen instant, for tests of the decisions taken over it.
    #[cfg(test)]
    pub(crate) fn at(unix: i64) -> Self {
        Self { unix }
    }

    /// Whether this reading is a host-clock fault.
    pub(crate) fn is_faulted(&self) -> bool {
        reading_is_faulted(self.unix)
    }

    /// The reading as whole Unix seconds, for a consumer that compares against it.
    pub(crate) fn unix_seconds(&self) -> i64 {
        self.unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole seconds since the epoch at 2020-01-01T00:00:00Z. Any host this test runs
    /// on reads later than that, so a reading below it means the conversion is wrong
    /// rather than that the clock is merely skewed.
    const YEAR_2020: i64 = 1_577_836_800;

    #[test]
    fn reads_a_plausible_present_instant() {
        assert!(
            now_unix() > YEAR_2020,
            "expected a post-2020 reading, got {}",
            now_unix()
        );
    }

    #[test]
    fn does_not_run_backwards_between_reads() {
        let first = now_unix();
        let second = now_unix();
        assert!(second >= first, "{second} preceded {first}");
    }

    #[test]
    fn a_sane_host_clock_is_not_diagnosed_as_faulted() {
        // The clamp contract, from the consuming side: `reading_is_faulted` exists to
        // catch the `0` this function produces for a pre-epoch error, so a working host
        // must not trip it — otherwise startup would refuse on every boot.
        assert!(!reading_is_faulted(now_unix()));
        assert!(!StartupReading::read().is_faulted());
    }

    /// The sentinel `now_unix()` produces for a pre-epoch `SystemTime` error, and the
    /// unset-clock reading it stands in for, must both be faults. A predicate that only
    /// caught literal 0 would pass a host reading a few days past the epoch.
    #[test]
    fn an_epoch_or_pre_epoch_clock_reading_is_a_fault() {
        assert!(reading_is_faulted(0));
        assert!(reading_is_faulted(-1));
        assert!(reading_is_faulted(86_400));
        assert!(reading_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1));
        assert!(StartupReading::at(0).is_faulted());
    }

    /// The threshold is far enough below any real deployment time that a correct clock
    /// never trips it — otherwise the warning would fire on every start and stop meaning
    /// anything.
    #[test]
    fn a_plausible_deployment_clock_is_not_a_fault() {
        assert!(!reading_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS));
        // 2026-01-01 UTC.
        assert!(!reading_is_faulted(1_767_225_600));
        assert!(!reading_is_faulted(i64::MAX));
        assert!(!StartupReading::at(1_767_225_600).is_faulted());
    }
}
