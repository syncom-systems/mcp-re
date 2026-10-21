// SPDX-License-Identifier: Apache-2.0
//! The statement that a deployment requires no durable commitment before dispatch.
//!
//! *This deployment observes on a best-effort basis and commits nothing* is a fact about the
//! deployment's [`AuditPosture`](super::AuditPosture). The disposition that carries it past
//! the intent crossing lives in [`crate::request_stages`], a module that cannot see the
//! posture's representation. Without a statement its `NotRequired` arm would be a value any
//! caller could write: a required deployment handed a `NotRequired` disposition would
//! dispatch with no intent committed, and nothing downstream could tell.
//!
//! [`NoCommitmentRequired`] carries the posture owner's statement. It is NOT a fake witness:
//! it says no witness was owed, never that one was obtained.

/// A statement, made by the audit-posture owner and carried in `IntentDisposition::NotRequired`,
/// that the deployment runs the best-effort posture.
#[derive(Debug)]
pub(crate) struct NoCommitmentRequired {
    /// Private, so no struct literal outside this module can state it.
    _sealed: (),
}

impl NoCommitmentRequired {
    /// The owner's statement. Visible to the audit-commitment module tree only, and used only
    /// where the posture holds no required commitment.
    pub(in crate::audit_commitment) fn minted_by_posture() -> Self {
        NoCommitmentRequired { _sealed: () }
    }

    /// A statement for a test that builds a `NotRequired` disposition directly. Test builds
    /// only: no production path can reach it.
    #[cfg(test)]
    pub(crate) fn for_a_test() -> Self {
        NoCommitmentRequired { _sealed: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The statement exists and is distinguishable from nothing at all: holding one is the
    /// only way to inhabit a `NotRequired` arm.
    #[test]
    fn the_statement_is_a_value_the_owner_hands_out() {
        let statement = NoCommitmentRequired::minted_by_posture();
        assert!(format!("{statement:?}").contains("NoCommitmentRequired"));
    }
}
