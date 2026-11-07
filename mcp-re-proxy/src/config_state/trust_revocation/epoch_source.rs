// SPDX-License-Identifier: Apache-2.0
//! The borrowed view of a state's networked epoch source.

/// Where the trust epoch counter lives, as a borrowed view of the state that carries one.
///
/// The locator and the key are handed over TOGETHER because they were validated together
/// and are meaningless apart: a counter read from the right store under the wrong key
/// reports an epoch that never advances, which is a revocation channel that silently
/// stops revoking. Borrowed, so it reads a state without being able to assemble one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSource<'a> {
    pub(in crate::config_state::trust_revocation) url: &'a str,
    pub(in crate::config_state::trust_revocation) key: &'a str,
}

impl<'a> EpochSource<'a> {
    /// Where the epoch counter lives.
    pub fn url(&self) -> &'a str {
        self.url
    }

    /// Which key holds the counter, already resolved against the default.
    pub fn key(&self) -> &'a str {
        self.key
    }
}
