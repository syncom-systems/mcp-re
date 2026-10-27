// SPDX-License-Identifier: Apache-2.0
//! The capability to publish a success the exchange has already decided it may publish.
//!
//! [`ExchangeProgress::may_publish`](super::ExchangeProgress::may_publish) is the only
//! producer and [`ExchangeProgress::publish`](super::ExchangeProgress::publish) the only
//! consumer. The field is visible to `exchange_state` alone, so no other code can construct a
//! permit or open one, and "decide, then publish" is a fact about the types rather than about
//! the order of two calls at each success exit.

use super::ServedSuccess;

/// A success [`may_publish`](super::ExchangeProgress::may_publish) cleared, carried to the
/// [`publish`](super::ExchangeProgress::publish) that drives its tail.
#[must_use = "a cleared success is published or refused, never dropped"]
pub(crate) struct PublishPermit<D>(pub(super) ServedSuccess<D>);

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
        assert_eq!(p.state(), ExchangeState::Dispatched, "decided, not entered");
        p.publish(permit);
        assert_eq!(p.state(), ExchangeState::AcknowledgedNotification);
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
