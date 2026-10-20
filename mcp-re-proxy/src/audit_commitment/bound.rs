// SPDX-License-Identifier: Apache-2.0
//! How long the request path waits for a commitment authority to answer.

use std::time::Duration;

use crate::config_state::connection_bounds::DEFAULT_TIMEOUT;

/// The longest commitment wait this type admits: the default request deadline. A
/// commitment that outlasts the request it gates cannot gate it.
///
/// This type does not know a deployment's configured deadline. It refuses a zero and
/// anything above this ceiling; relating the bound to a configured deadline is the job of
/// whatever chooses it.
pub(crate) const MAX_COMMITMENT_BOUND: Duration = DEFAULT_TIMEOUT;

/// A nonzero wait, at most [`MAX_COMMITMENT_BOUND`].
///
/// Zero is refused rather than read as "no wait": a zero timeout fires before the provider
/// is even asked, so every commitment would be `Uncertain(TimedOut)` and the posture would
/// be indistinguishable from an outage (the `async_etcd_store` precedent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommitmentBound(Duration);

impl CommitmentBound {
    /// `wait`, or `None` when it is zero or above [`MAX_COMMITMENT_BOUND`].
    #[cfg_attr(not(test), allow(dead_code))] // no production caller chooses a bound yet; G1 is its consumer
    pub(crate) fn new(wait: Duration) -> Option<Self> {
        (!wait.is_zero() && wait <= MAX_COMMITMENT_BOUND).then_some(CommitmentBound(wait))
    }

    /// The wait.
    pub(crate) fn get(self) -> Duration {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_bound_is_refused() {
        assert_eq!(CommitmentBound::new(Duration::ZERO), None);
        assert_eq!(
            CommitmentBound::new(Duration::from_nanos(1)).map(CommitmentBound::get),
            Some(Duration::from_nanos(1))
        );
    }

    #[test]
    fn a_bound_above_the_request_deadline_ceiling_is_refused() {
        let over = MAX_COMMITMENT_BOUND
            .checked_add(Duration::from_nanos(1))
            .expect("representable");
        assert_eq!(CommitmentBound::new(over), None);
    }

    #[test]
    fn a_bound_at_the_ceiling_is_the_last_legal_value() {
        assert_eq!(
            CommitmentBound::new(MAX_COMMITMENT_BOUND).map(CommitmentBound::get),
            Some(DEFAULT_TIMEOUT)
        );
    }
}
