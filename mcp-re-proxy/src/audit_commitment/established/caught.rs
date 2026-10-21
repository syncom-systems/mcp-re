// SPDX-License-Identifier: Apache-2.0
//! Polling a provider's future so that its panic becomes an answer.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::super::{CommitFuture, CommitmentReceipt, ProviderFailure};

/// The provider's future panicked while it was polled.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Panicked;

/// A provider's future, polled under `catch_unwind`.
///
/// A panic inside a provider is a typed answer here, never an unwind into the connection
/// task and never a swallow: the observer's `record_to` discards its sink's panic because an
/// observer cannot affect the request, and an authority's panic is exactly the opposite
/// kind of fact.
pub(super) struct Caught<'a> {
    inner: CommitFuture<'a>,
}

impl<'a> Caught<'a> {
    /// Poll `inner` under `catch_unwind`.
    pub(super) fn new(inner: CommitFuture<'a>) -> Self {
        Caught { inner }
    }
}

impl Future for Caught<'_> {
    type Output = Result<Result<CommitmentReceipt, ProviderFailure>, Panicked>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // AssertUnwindSafe holds: after a panic this returns Ready, the caller drops the
        // future without polling it again, and no owner state is read from it.
        match catch_unwind(AssertUnwindSafe(|| self.inner.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(answer)) => Poll::Ready(Ok(answer)),
            Err(_) => Poll::Ready(Err(Panicked)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panic_while_polled_is_an_answer() {
        let panicking: CommitFuture<'static> = Box::pin(async { panic!("provider fault") });
        assert_eq!(Caught::new(panicking).await, Err(Panicked));
    }

    #[tokio::test]
    async fn an_answer_passes_through_unchanged() {
        let failing: CommitFuture<'static> = Box::pin(async { Err(ProviderFailure::Unavailable) });
        assert_eq!(
            Caught::new(failing).await,
            Ok(Err(ProviderFailure::Unavailable))
        );
    }
}
