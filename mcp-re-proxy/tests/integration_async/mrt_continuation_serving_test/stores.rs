// SPDX-License-Identifier: Apache-2.0
//! A continuation store with one operation made to fail, for the shared-tier outage cases.

use std::sync::Arc;

use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::Consumption;
use mcp_re_proxy::continuation_store::ContinuationFuture;
use mcp_re_proxy::continuation_store::ContinuationKey;
use mcp_re_proxy::continuation_store::ContinuationStoreError;
use mcp_re_proxy::continuation_store::Creation;
use mcp_re_proxy::continuation_store::RetainedHandles;

/// The one store operation that fails.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Outage {
    /// WRITES fail, so an exchange reaches the open-leg record and fails only there.
    Create,
    /// Reads fail, so an answer leg fails at exactly the read the shared tier serves it from.
    Peek,
    /// `consume` never answers — the `DEL`-with-a-lost-reply case, where the entry may or
    /// may not be gone.
    Consume,
}

/// A store that behaves normally except for one [`Outage`].
pub(super) struct OutageStore {
    inner: Arc<dyn AsyncContinuationStore>,
    outage: Outage,
}

impl OutageStore {
    pub(super) fn over(
        inner: Arc<dyn AsyncContinuationStore>,
        outage: Outage,
    ) -> Arc<dyn AsyncContinuationStore> {
        Arc::new(Self { inner, outage })
    }

    fn unavailable<'a, T: Send + 'a>() -> ContinuationFuture<'a, T> {
        Box::pin(async {
            Err(ContinuationStoreError::Unavailable {
                details: "the shared tier is down".to_string(),
            })
        })
    }
}

impl AsyncContinuationStore for OutageStore {
    fn create<'a>(
        &'a self,
        key: &'a ContinuationKey,
        bases: &'a RetainedHandles,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, Creation> {
        match self.outage {
            Outage::Create => Self::unavailable(),
            _ => self.inner.create(key, bases, ttl_secs),
        }
    }

    fn peek<'a>(
        &'a self,
        key: &'a ContinuationKey,
    ) -> ContinuationFuture<'a, Option<RetainedHandles>> {
        match self.outage {
            Outage::Peek => Self::unavailable(),
            _ => self.inner.peek(key),
        }
    }

    fn consume<'a>(&'a self, key: &'a ContinuationKey) -> ContinuationFuture<'a, Consumption> {
        match self.outage {
            Outage::Consume => Self::unavailable(),
            _ => self.inner.consume(key),
        }
    }
}
