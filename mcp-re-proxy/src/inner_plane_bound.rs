// SPDX-License-Identifier: Apache-2.0
//! Holding the inner plane's in-flight bound at or above the fleet's admission ceiling.
//!
//! The aggregate is the admission owner's
//! ([`InFlightLimitBasis::fleet_ceiling`]), over the shard count the host resolved once
//! ([`ResolvedTopology`]). What lives here is the raise and the announcement, together — the
//! raise and the line explaining it are one decision, and separating them is how a
//! transcript starts describing a bound the pool does not have.
//!
//! # Why the bound matters
//!
//! The pool is PROCESS-WIDE (one instance behind the `Arc` every core shares), so its
//! in-flight bound must not sit below the fleet's aggregate admission ceiling. If it did,
//! requests that passed every security gate would be answered with a signed `inner server
//! unavailable` at a capacity cliff no configured flag names — and the shedding decision
//! would move from the admission gate, where it is deliberate, to the inner pool, where it
//! is an accident of core count.

use crate::async_fleet::ResolvedTopology;
use crate::config_state::InFlightLimitBasis;
use crate::http_inner::HttpInnerPool;

/// Return `pool` bounded at or above the fleet admission ceiling, announcing any raise.
///
/// Raised only when the ceiling EXCEEDS the pool's default: equal is not a raise, or every
/// start would print a line saying nothing changed. Never lowered.
pub(crate) fn raised_to_fleet_ceiling(
    pool: HttpInnerPool,
    in_flight_limit: InFlightLimitBasis,
    topology: ResolvedTopology,
) -> HttpInnerPool {
    let shards = topology.shards();
    let raised = in_flight_limit.fleet_ceiling(shards);
    if raised.get() <= crate::http_inner::DEFAULT_MAX_IN_FLIGHT {
        return pool;
    }
    let cores = shards.get();
    eprintln!(
        "mcp-re-proxy: inner-plane in-flight bound raised to {raised} to stay at or \
         above the fleet admission ceiling ({cores} cores); the admission gate sheds, \
         not the inner pool."
    );
    pool.with_max_in_flight(raised)
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::raised_to_fleet_ceiling;
    use crate::async_fleet::ResolvedTopology;
    use crate::config_state::InFlightLimitBasis;
    use crate::http_inner::{HttpInnerPool, DEFAULT_MAX_IN_FLIGHT};

    fn requests(n: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(n).expect("the fixture count is not zero")
    }

    fn pool() -> HttpInnerPool {
        HttpInnerPool::from_url_strs(
            vec!["http://127.0.0.1:1".to_string()],
            std::time::Duration::from_secs(1),
        )
        .expect("a loopback URL builds a pool")
    }

    /// A four-core deployment, independent of the host's CPU count.
    fn four_cores() -> ResolvedTopology {
        ResolvedTopology::for_test(4, 1)
    }

    #[test]
    fn a_fleet_ceiling_above_the_default_raises_the_pool_to_it() {
        let per_core = InFlightLimitBasis::PerCore {
            requests: requests(2048),
        };
        let raised = raised_to_fleet_ceiling(pool(), per_core, four_cores());
        assert_eq!(raised.max_in_flight(), 8192, "2048 per core across 4 cores");

        let fleet = InFlightLimitBasis::FleetTotal {
            requests: requests(8192),
        };
        let raised = raised_to_fleet_ceiling(pool(), fleet, four_cores());
        assert_eq!(raised.max_in_flight(), 8192, "a fleet total is the ceiling");
    }

    #[test]
    fn a_fleet_ceiling_below_the_default_never_lowers_the_pool() {
        let basis = InFlightLimitBasis::PerCore {
            requests: requests(1),
        };
        let kept = raised_to_fleet_ceiling(pool(), basis, four_cores());
        assert_eq!(
            kept.max_in_flight(),
            DEFAULT_MAX_IN_FLIGHT,
            "the wiring raises the shared pool and never shrinks it"
        );
    }

    /// A ceiling exactly at the default is not a raise.
    #[test]
    fn a_fleet_ceiling_equal_to_the_default_keeps_the_pool() {
        let per_core = DEFAULT_MAX_IN_FLIGHT / 4;
        assert_eq!(
            per_core * 4,
            DEFAULT_MAX_IN_FLIGHT,
            "the fixture divides evenly"
        );
        let basis = InFlightLimitBasis::PerCore {
            requests: requests(per_core),
        };
        let kept = raised_to_fleet_ceiling(pool(), basis, four_cores());
        assert_eq!(kept.max_in_flight(), DEFAULT_MAX_IN_FLIGHT);
    }
}
