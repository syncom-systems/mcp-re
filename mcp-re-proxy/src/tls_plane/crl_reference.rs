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
/// Possession means: either the reading is not a host-clock fault, or it was checked
/// under a posture that enforces no client CRL — and the reference remembers which, so a
/// reference checked without CRLs cannot be spent on a plan that loads them
/// ([`CrlReference::for_paths`]). Nothing is `Stale` against a clock reading zero, so with
/// CRLs configured a faulted reading would declare an arbitrarily expired CRL fresh while
/// the revocation-posture transcript still advertised it as enforced.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CrlReference {
    unix: i64,
    checked_with_crls: bool,
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
            checked_with_crls: crl.is_enforced(),
        })
    }

    /// The reference as whole Unix seconds for loading `crl_paths`, or a refusal when the
    /// loader reads any CRL and this reference was checked under a posture that reads none:
    /// such a reference may hold a faulted reading the fault check never had cause to
    /// refuse.
    pub(super) fn for_paths(&self, crl_paths: &[String]) -> Result<i64, String> {
        if !crl_paths.is_empty() && !self.checked_with_crls {
            return Err(
                "mcp-re-proxy refuses to start: the CRL freshness reference was checked \
                 against a posture with no client CRL, but the TLS plane is loading CRLs; \
                 the reference and the plan must come from one deployment"
                    .to_string(),
            );
        }
        Ok(self.unix)
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
        assert_eq!(
            sane.for_paths(&["/a.crl".to_string()]),
            Ok(EPOCH_CLOCK_FAULT_THRESHOLD_SECS)
        );
    }

    /// A reference checked under a posture with no CRL cannot be spent on a plan that loads
    /// CRLs: with a faulted reading it would hand the loader a zero instant the fault check
    /// never refused.
    ///
    /// The broken implementation this catches: a reference that keeps only the instant, so
    /// any `CrlReference` serves any plan.
    #[test]
    fn a_reference_checked_without_crls_does_not_serve_a_plan_that_loads_them() {
        let unchecked = CrlReference::of(&StartupReading::at(0), &crl_posture(&[]))
            .expect("no CRL posture tolerates a faulted clock");
        let refusal = unchecked
            .for_paths(&["/a.crl".to_string()])
            .expect_err("a plan that loads CRLs must refuse a reference checked without them");
        assert!(refusal.contains("CRL"), "{refusal}");
        assert_eq!(
            unchecked.for_paths(&[]),
            Ok(0),
            "the same reference still serves a plan that loads no CRL"
        );
    }
}
