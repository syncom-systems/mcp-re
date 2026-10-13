// SPDX-License-Identifier: Apache-2.0
//! The test-flavor producer of an [`ActiveDelegatedKey`]: the caller states its parts.
//!
//! Compiled only under `test` or the test-only `pre_052_fixtures` feature, so a product
//! build has [`ActiveDelegatedKey::issued`] as the key's sole producer.
#![cfg(any(test, feature = "pre_052_fixtures"))]

use std::sync::Arc;

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;

use super::ActiveDelegatedKey;

impl ActiveDelegatedKey {
    /// A key whose parts the CALLER states: no credential is read, and nothing relates the
    /// key, the identity, the credential and `delegated_kid` to each other.
    ///
    /// The name is the contract: this establishes only that the caller said so. The
    /// batteries that need it sign what a verifier must refuse — a credential for another
    /// key, an identity naming a keyid the credential did not confirm, bytes that are not a
    /// credential at all. A stated key carries no window of its own: `jti` is empty and
    /// `nbf`/`exp` span every instant, and [`SigningWindow::stated`](crate::custody::SigningWindow::stated)
    /// states the validity a signature advertises.
    ///
    /// Compiled only under `test` or the test-only `pre_052_fixtures` feature, so a product
    /// build has [`issued`](Self::issued) as its sole producer.
    pub fn stated(
        key: SigningKey,
        server_signer: ActorIdentity,
        credential: impl Into<String>,
        delegated_kid: impl Into<String>,
    ) -> Self {
        ActiveDelegatedKey {
            key: Arc::new(key),
            server_signer,
            credential: credential.into(),
            delegated_kid: delegated_kid.into(),
            jti: String::new(),
            nbf: i64::MIN,
            exp: i64::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stated key carries exactly the parts the caller gave it, related to nothing: the
    /// keyid it signs under need not be the one its identity names.
    #[test]
    fn a_stated_key_carries_what_the_caller_stated() {
        let identity = ActorIdentity {
            role: "server".into(),
            trust_domain: "example.test".into(),
            subject: "srv".into(),
            keyid: "block-kid".into(),
        };
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let public = key.public_key().to_bytes();
        let stated = ActiveDelegatedKey::stated(key, identity, "not-a-credential", "wire-kid");
        assert_eq!(stated.server_signer().keyid, "block-kid");
        assert_eq!(stated.delegated_kid(), "wire-kid");
        assert_eq!(stated.credential(), "not-a-credential");
        assert_eq!(stated.public_key().to_bytes(), public);
        assert_eq!(
            (stated.nbf(), stated.exp(), stated.jti()),
            (i64::MIN, i64::MAX, "")
        );
    }
}
