//! The [`InvalidationChannel`] view of a shared [`TrustEpochSource`].

use super::EpochReader;
use super::TrustEpochSource;
use crate::trust_plane::InvalidationChannel;
use crate::trust_plane::InvalidationEvent;

/// An [`InvalidationChannel`] view of a shared [`TrustEpochSource`], so the poller
/// thread and the request path hold the same source.
pub struct SharedEpochChannel<R: EpochReader>(pub std::sync::Arc<TrustEpochSource<R>>);

impl<R: EpochReader> InvalidationChannel for SharedEpochChannel<R> {
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        self.0.drain_pending()
    }
    fn is_healthy(&self) -> bool {
        self.0.is_healthy()
    }
}
