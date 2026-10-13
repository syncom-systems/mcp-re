// SPDX-License-Identifier: Apache-2.0
//! What a delegated signature is made under, read from one [`SigningWindow`].
//!
//! The response emitters in `sign`, `bodyless` and `rejection` take this projection and
//! nothing else, so the identity a block names, the credential it carries, the key that
//! signs, the RFC 9421 `keyid` and the advertised validity are read from ONE window. The
//! window's [`ActiveDelegatedKey`](super::ActiveDelegatedKey) owns that the block's
//! `server_signer.keyid` is the credential's `delegated_kid`; an emitter has nothing left
//! to re-check, because no caller can hand it parts that disagree.

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;

use super::SigningWindow;

/// The parts of a [`SigningWindow`] a delegated emitter signs with. Crate-private, and
/// produced only from a window.
pub(crate) struct DelegatedSigner<'a> {
    window: &'a SigningWindow,
}

impl<'a> DelegatedSigner<'a> {
    /// The projection of `window`.
    pub(super) fn of(window: &'a SigningWindow) -> Self {
        DelegatedSigner { window }
    }

    /// The identity the response evidence block names as its signer.
    pub(crate) fn server_signer(&self) -> &'a ActorIdentity {
        self.window.key().server_signer()
    }

    /// The compact-JWS delegation credential the response carries.
    pub(crate) fn credential(&self) -> &'a str {
        self.window.key().credential()
    }

    /// The delegated signing key. Never the root.
    pub(crate) fn key(&self) -> &'a SigningKey {
        self.window.key().key()
    }

    /// The RFC 9421 `keyid` the signature is made under: the credential's `delegated_kid`.
    pub(crate) fn kid(&self) -> &'a str {
        self.window.key().delegated_kid()
    }

    /// Unix seconds the signature advertises its validity from.
    pub(crate) fn created(&self) -> i64 {
        self.window.created()
    }

    /// Unix seconds the signature may claim validity until.
    pub(crate) fn expires(&self) -> i64 {
        self.window.expires()
    }
}

#[cfg(test)]
mod tests {
    use super::super::signing_window::tests::key;
    use super::*;

    /// Every part an emitter signs with is the window's own: the block's signer keyid and
    /// the signature keyid are one value, and the validity is the window's.
    #[test]
    fn every_part_is_read_from_the_one_window() {
        let window = SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential");
        let signer = window.signer();
        assert_eq!(signer.server_signer().keyid, signer.kid());
        assert_eq!(signer.kid(), window.key().delegated_kid());
        assert_eq!(signer.credential(), window.key().credential());
        assert_eq!(
            signer.key().public_key().to_bytes(),
            window.key().public_key().to_bytes()
        );
        assert_eq!((signer.created(), signer.expires()), (1_000, 1_030));
    }
}
