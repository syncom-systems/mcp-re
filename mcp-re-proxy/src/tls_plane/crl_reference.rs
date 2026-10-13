// SPDX-License-Identifier: Apache-2.0
//! The reference instant the boot-time client-CRL freshness refusal compares against.
//!
//! [`crate::tls_plane::TlsPlane::materialize`] takes a [`CrlReference`], and the only way to
//! hold one is [`CrlReference::of`], which refuses a faulted startup reading exactly where
//! the fault would disable that refusal. So a faulted clock cannot reach the CRL comparison
//! because the plane cannot be materialized without passing through this check, not
//! because the composition root ran a check before it called the plane.

use crate::clock::StartupReading;
use crate::config_state::CrlRevocationState;

/// A startup reading the CRL freshness refusal may compare against.
///
/// Possession means: either this deployment enforces no client CRL, or the reading is not
/// a host-clock fault. Nothing is `Stale` against a clock reading zero, so with CRLs
/// configured a faulted reading would declare an arbitrarily expired CRL fresh while the
/// revocation-posture transcript still advertised it as enforced.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CrlReference {
    unix: i64,
}

impl CrlReference {
    /// The CRL freshness reference for `reading` under the deployment's CRL posture.
    ///
    /// A faulted clock costs a refusal only where it disables a refusal: with no client
    /// CRL enforced it is tolerable here, because what remains is per-request freshness,
    /// which fails closed. The posture arrives as the owner's value: whether this
    /// deployment enforces offline revocation is `CrlRevocationState`'s answer.
    pub(crate) fn of(
        reading: &StartupReading,
        crl: &CrlRevocationState,
    ) -> Result<CrlReference, String> {
        if crl.is_enforced() && reading.is_faulted() {
            let configured_crls = crl.paths().len();
            return Err(format!(
                "mcp-re-proxy refuses to start: the system clock reads at/near the Unix epoch \
                 ({} < {}s), so the boot-time client-CRL freshness refusal cannot be \
                 performed — every CRL compares as fresh against a zero clock, and the \
                 {configured_crls} configured CRL(s) would be advertised as enforced while an \
                 arbitrarily expired one was loaded. Fix the host clock (NTP/RTC) before starting.",
                reading.unix_seconds(),
                crate::clock::EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
            ));
        }
        Ok(CrlReference {
            unix: reading.unix_seconds(),
        })
    }

    /// The reference as whole Unix seconds, for the CRL loader's `nextUpdate` comparison.
    pub(super) fn unix_seconds(&self) -> i64 {
        self.unix
    }
}

#[cfg(test)]
mod tests {
    use super::CrlReference;
    use crate::clock::StartupReading;
    use crate::clock::EPOCH_CLOCK_FAULT_THRESHOLD_SECS;
    use crate::config_state::CrlRevocationState;

    fn crl_posture(paths: &[&str]) -> CrlRevocationState {
        crate::config_state::test_support::crl_posture(paths, None)
    }

    /// A faulted clock is tolerable where it only feeds per-request freshness, which then
    /// fails closed. With client CRLs configured it costs the boot-time stale-CRL refusal,
    /// so no reference exists and startup refuses.
    ///
    /// The broken implementation this catches: producing a reference unconditionally, so
    /// the same faulted reading reaches the CRL loader as its freshness instant.
    #[test]
    fn a_faulted_clock_refuses_only_when_it_disables_the_crl_refusal() {
        let refusal = CrlReference::of(&StartupReading::at(0), &crl_posture(&["/a.crl"]))
            .expect_err("a faulted clock plus CRLs must refuse");
        assert!(
            refusal.contains("CRL") && refusal.contains("clock"),
            "the refusal must name both halves of why it fired: {refusal}"
        );
        assert!(
            CrlReference::of(
                &StartupReading::at(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1),
                &crl_posture(&["/a.crl", "/b.crl"]),
            )
            .is_err(),
            "anything below the fault threshold disables the same refusal"
        );
        // The two negative controls. Without them a reference that never existed would
        // satisfy the assertions above.
        assert!(
            CrlReference::of(&StartupReading::at(0), &crl_posture(&[])).is_ok(),
            "with no CRL configured there is no boot-time refusal to disable; the \
             per-request posture is already fail-closed and warns"
        );
        let sane = CrlReference::of(
            &StartupReading::at(EPOCH_CLOCK_FAULT_THRESHOLD_SECS),
            &crl_posture(&["/a.crl", "/b.crl", "/c.crl"]),
        )
        .expect("a sane clock must not be refused however many CRLs are configured");
        assert_eq!(sane.unix_seconds(), EPOCH_CLOCK_FAULT_THRESHOLD_SECS);
    }
}
