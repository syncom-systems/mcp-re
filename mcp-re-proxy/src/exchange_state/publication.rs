// SPDX-License-Identifier: Apache-2.0
//! The capability to publish a success the exchange has already decided it may publish.
//!
//! [`ExchangeProgress::may_publish`](super::ExchangeProgress::may_publish) is the only
//! producer, and [`PublishPermit::publish`] the only consumer. The fields are private to this
//! module, so no other code can construct a permit or open one, and "decide, then publish" is
//! a fact about the types rather than about the order of two calls at each success exit.
//!
//! A permit holds the exclusive borrow of the exchange that cleared it, and publishes to that
//! exchange alone. So a permit cleared on one exchange cannot drive another's terminal, and
//! while it lives the cleared exchange can be read but not advanced, replaced or swapped:
//! the state `publish` drives is the state `may_publish` judged.

use super::{ExchangeProgress, ServedSuccess};

/// A success [`may_publish`](super::ExchangeProgress::may_publish) cleared, bound to the
/// exchange that cleared it until [`publish`](Self::publish) drives its tail there.
#[must_use = "a cleared success is published or refused, never dropped"]
pub(crate) struct PublishPermit<'x, D> {
    exchange: &'x mut ExchangeProgress,
    served: ServedSuccess<D>,
}

impl<'x, D> PublishPermit<'x, D> {
    /// The permit for `served`, on the exchange that cleared it.
    pub(super) fn issue(exchange: &'x mut ExchangeProgress, served: ServedSuccess<D>) -> Self {
        Self { exchange, served }
    }

    /// The cleared exchange, read between the decision and the terminal.
    #[cfg(test)]
    pub(crate) fn exchange(&self) -> &ExchangeProgress {
        self.exchange
    }

    /// Give the cleared exchange back to a refusal between the decision and the terminal.
    ///
    /// Consumes the permit, so nothing done through the returned borrow can then be
    /// published: the refusal enters its own terminal on the exchange, unpublished.
    pub(crate) fn withdraw(self) -> &'x mut ExchangeProgress {
        self.exchange
    }

    /// Reach the terminal this permit names, on the exchange that cleared it.
    pub(crate) fn publish(self) {
        for event in self.served.tail() {
            self.exchange.advance(*event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Established, ExchangeEvent, ExchangeProgress, ExchangeState, ResponseOrigin, ServedSuccess,
    };
    use crate::http_profile_serve::inner_plane::NotificationDelivered;

    fn dispatched() -> ExchangeProgress {
        use ExchangeEvent as E;
        let mut p = ExchangeProgress::new();
        for e in [
            E::SignatureVerified,
            E::TransportBindingChecked,
            E::AdmissionCurrencyChecked,
            E::ContinuationPrepared,
            E::ReplayAdmitted,
            E::DelegatedKeySnapshotted,
            E::ContinuationRetired,
            E::ForwardBodyPrepared,
            E::InnerPlaneAccepted,
            E::RetentionCommitted,
            E::BackendDispatched,
        ] {
            p.advance(e);
        }
        assert_eq!(p.state(), ExchangeState::Dispatched);
        p
    }

    fn acknowledged() -> ServedSuccess<NotificationDelivered> {
        ServedSuccess::Acknowledged(Established::new(
            NotificationDelivered::for_a_test(),
            ExchangeEvent::NotificationAcknowledged,
        ))
    }

    /// The permit is the only way to the terminal, and it reaches the terminal it was cleared for.
    #[test]
    fn a_permit_from_may_publish_publishes_to_the_terminal() {
        let mut p = dispatched();
        let permit = p
            .may_publish(acknowledged())
            .expect("a coherent 202 is cleared");
        assert_eq!(
            permit.exchange().state(),
            ExchangeState::Dispatched,
            "decided, not entered"
        );
        permit.publish();
        assert_eq!(p.state(), ExchangeState::AcknowledgedNotification);
        assert_eq!(p.anomaly(), None);
    }

    /// A permit publishes to the exchange that cleared it. A second exchange in the same
    /// state, one whose own decision would refuse, is untouched.
    #[test]
    fn a_permit_publishes_only_to_the_exchange_that_cleared_it() {
        let mut cleared = dispatched();
        let mut other = dispatched();
        other.observe_origin(ResponseOrigin::DispatchIndeterminate);
        cleared
            .may_publish(acknowledged())
            .expect("the coherent exchange is cleared")
            .publish();
        assert_eq!(cleared.state(), ExchangeState::AcknowledgedNotification);
        assert_eq!(
            other.state(),
            ExchangeState::Dispatched,
            "never decided, never entered"
        );
        assert!(other.may_publish(acknowledged()).is_err());
        assert_eq!(other.state(), ExchangeState::Dispatched);
    }

    /// A refusal between the decision and the terminal withdraws the permit and refuses the
    /// exchange it cleared: the exchange ends `FailedAfterDispatch`, never at the success
    /// terminal the permit named, and coherent.
    #[test]
    fn a_withdrawn_permit_leaves_its_exchange_to_the_refusal() {
        let mut p = dispatched();
        let permit = p
            .may_publish(acknowledged())
            .expect("a coherent 202 is cleared");
        permit.withdraw().advance(ExchangeEvent::Refused);
        assert_eq!(p.state(), ExchangeState::FailedAfterDispatch);
        assert_eq!(p.anomaly(), None);
    }

    /// A refused publication yields no permit, so nothing exists that could publish it.
    #[test]
    fn a_refused_publication_yields_no_permit() {
        let mut p = dispatched();
        p.observe_origin(ResponseOrigin::DispatchIndeterminate);
        assert_eq!(
            p.may_publish(acknowledged()).err(),
            Some("synthesized transport-failure bytes were served as a success")
        );
        assert_eq!(p.state(), ExchangeState::Dispatched);
    }
}
