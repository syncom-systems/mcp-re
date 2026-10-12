// SPDX-License-Identifier: Apache-2.0
//! What a continuation leg is refused with, classified once for every caller.
//!
//! Every caller of the plane — the serving assembly and the HTTP-profile proof front —
//! signs its receipt from this value, so no caller decides which wire code a store
//! outage, a taken key or a spent approval earns.

use mcp_re_core::McpReError;

use crate::refusal::Refusal;

/// Why a continuation leg cannot proceed.
///
/// Three values, because the three facts carry different retry meanings: a deployment
/// that could not answer, a store that answered "taken", and a store that answered "no
/// live approval".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuationRefusal {
    /// The shared tier did not answer, holds its live-entry bound, or this deployment holds
    /// no correlation capability. A fact about the deployment, never the caller's forged
    /// continuation, and a retry may succeed.
    Unavailable,
    /// The store answered that a live approval for this actor and `requestState` is
    /// already outstanding. A retry finds the same thing.
    Conflict,
    /// The store answered that there was no live approval to spend: already answered,
    /// expired, or spliced. A statement about the caller.
    AlreadyAnswered,
}

impl ContinuationRefusal {
    /// The frozen wire error this refusal is reported as.
    pub fn error(self) -> McpReError {
        match self {
            ContinuationRefusal::Unavailable => McpReError::ReplayCacheUnavailable,
            ContinuationRefusal::Conflict => McpReError::ContinuationConflict,
            ContinuationRefusal::AlreadyAnswered => McpReError::ContinuationBindingFailed,
        }
    }

    /// The HTTP status the receipt carries.
    pub fn status(self) -> u16 {
        match self {
            ContinuationRefusal::Unavailable => 503,
            ContinuationRefusal::Conflict | ContinuationRefusal::AlreadyAnswered => 409,
        }
    }
}

impl From<ContinuationRefusal> for Refusal {
    fn from(refusal: ContinuationRefusal) -> Self {
        Refusal::new(refusal.error(), refusal.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each refusal keeps the classification the serving path has always signed: a
    /// deployment fact at 503, and the two answers about the caller's key at 409 with
    /// their own codes.
    #[test]
    fn each_refusal_keeps_its_wire_classification() {
        let table = [
            (
                ContinuationRefusal::Unavailable,
                McpReError::ReplayCacheUnavailable,
                503,
            ),
            (
                ContinuationRefusal::Conflict,
                McpReError::ContinuationConflict,
                409,
            ),
            (
                ContinuationRefusal::AlreadyAnswered,
                McpReError::ContinuationBindingFailed,
                409,
            ),
        ];
        for (refusal, error, status) in table {
            assert_eq!(refusal.error(), error, "{refusal:?}");
            assert_eq!(refusal.status(), status, "{refusal:?}");
            let served = Refusal::from(refusal);
            assert_eq!(served.status, status);
            assert_eq!(served.cause, crate::refusal::RefusalCause::from(error));
        }
    }
}
