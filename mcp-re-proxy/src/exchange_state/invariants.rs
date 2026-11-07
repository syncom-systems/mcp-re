// SPDX-License-Identifier: Apache-2.0
//! The cross-machine invariants of an exchange's tuple, as one predicate.

use super::{BackendState, ExchangeProgress, ExchangeState, OpenLeg, ResponseOrigin};

impl ExchangeProgress {
    /// The cross-machine invariants, as one predicate over the tuple.
    ///
    /// `None` means the tuple is coherent. These are the combinations that the transition
    /// relation alone cannot rule out, because they are agreements BETWEEN projections and
    /// `transition` sees only one of them.
    pub(super) fn invariant_violation(&self) -> Option<&'static str> {
        self.open_leg_violation()
            .or_else(|| self.synthesized_success_violation())
            .or_else(|| self.backend_projection_violation())
    }

    /// P2. An open leg may be claimed only once it can actually be answered. The
    /// obligation is incurred at classification and discharged only by the durable
    /// record; reaching a success terminal with it outstanding is MCP-RE telling a client
    /// to continue an exchange it has kept nothing to continue from.
    fn open_leg_violation(&self) -> Option<&'static str> {
        let unrecorded = self.request == ExchangeState::CompletedContinuationOpen
            && self.open_leg != OpenLeg::Recorded;
        let leg_in_terminal = self.request == ExchangeState::CompletedTerminal
            && self.open_leg != OpenLeg::NotApplicable;
        unrecorded
            .then_some("an open leg was served without a durable continuation record")
            .or(leg_in_terminal
                .then_some("a reply that opens a leg was served as a terminal completion"))
    }

    /// Bytes MCP-RE synthesized because the transport failed are a report ABOUT the
    /// exchange, never the exchange's own successful answer. Serving them as one is the
    /// signed-200-carrying-a-timeout case.
    fn synthesized_success_violation(&self) -> Option<&'static str> {
        (self.request.is_success_terminal() && self.origin == ResponseOrigin::DispatchIndeterminate)
            .then_some("synthesized transport-failure bytes were served as a success")
    }

    /// The derived backend projection, asserted rather than assumed.
    fn backend_projection_violation(&self) -> Option<&'static str> {
        let dispatched = self.request.backend_may_have_executed();
        let expected = match dispatched {
            true => BackendState::Dispatched,
            false => BackendState::NotDispatched,
        };
        (self.backend != expected)
            .then_some("the backend projection disagrees with the exchange state")
    }
}
