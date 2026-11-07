// SPDX-License-Identifier: Apache-2.0
//! An admission source whose authority can be taken down.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_proxy::admission_source::AdmissionFuture;
use mcp_re_proxy::admission_source::AdmissionSourceError;
use mcp_re_proxy::admission_source::AnsweredAs;
use mcp_re_proxy::admission_source::AsyncAdmissionSource;
use mcp_re_proxy::admission_source::InMemoryAdmissionSource;

use super::fixtures::admission_store;
use super::fixtures::publish_admitted;

/// A source whose authority can be taken down: lookups fail as unavailable while `down`,
/// and otherwise answer from the wrapped store. The in-process store cannot be unreachable
/// on its own, so the outage lives in this double and not in production code.
pub(super) struct OutageSwitch {
    store: InMemoryAdmissionSource,
    down: AtomicBool,
}

impl OutageSwitch {
    /// A reachable authority that has admitted the workload at `generation`.
    pub(super) fn admitting(generation: u64) -> Arc<Self> {
        let store = admission_store();
        publish_admitted(&store, generation);
        Arc::new(OutageSwitch {
            store,
            down: AtomicBool::new(false),
        })
    }

    pub(super) fn set_unavailable(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }
}

impl AsyncAdmissionSource for OutageSwitch {
    fn current<'a>(&'a self, admission_id: &'a str, now: i64) -> AdmissionFuture<'a, AnsweredAs> {
        if self.down.load(Ordering::SeqCst) {
            return Box::pin(async move {
                Err(AdmissionSourceError::Unavailable {
                    details: "injected outage".to_owned(),
                })
            });
        }
        self.store.current(admission_id, now)
    }
}
