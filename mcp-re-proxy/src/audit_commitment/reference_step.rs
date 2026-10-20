// SPDX-License-Identifier: Apache-2.0
//! The reference authority's script: what it answers to each commit. Test-only flavors,
//! like the authority.

use std::sync::Arc;

use super::reference::Forgery;
use super::RejectReason;

/// One scripted answer. An exhausted script answers [`Step::Commit`].
#[derive(Debug, Clone)]
pub(crate) enum Step {
    /// Journal the event and acknowledge it. An identical retry is acknowledged again; the
    /// same identity with other content is `Rejected(IdentityConflict)`.
    Commit,
    /// Refuse with this reason.
    Reject(RejectReason),
    /// Report the provider unavailable.
    Unavailable,
    /// Never answer.
    Hang,
    /// Drop the acknowledgement after the send.
    DropCompletion,
    /// Panic while the answer is polled.
    PanicInPoll,
    /// Panic before any answer exists.
    PanicBeforeFuture,
    /// Acknowledge with a receipt that disagrees with the request.
    Forge(Forgery),
    /// Acknowledge with the receipt of the previous commit.
    ReplayPrevious,
    /// Journal the event, then never acknowledge: the store holds an intent the proxy never
    /// learns about (W2).
    CommitThenPark,
    /// Journal the event, run the hook, then acknowledge: something happens to the world
    /// between the commit and the crossing it gates (W3).
    CommitThen(Hook),
}

/// A side effect a [`Step::CommitThen`] runs after it journals.
#[derive(Clone)]
pub(crate) struct Hook(pub(crate) Arc<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hook")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hook is opaque in debug output: what it does is the test's, not the script's.
    #[test]
    fn a_hook_prints_as_a_hook() {
        let hook = Hook(Arc::new(|| {}));
        assert_eq!(format!("{:?}", Step::CommitThen(hook)), "CommitThen(Hook)");
    }
}
