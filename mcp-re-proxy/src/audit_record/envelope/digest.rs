// SPDX-License-Identifier: Apache-2.0
//! The content identity of one event's canonical bytes.

use sha2::{Digest, Sha256};

/// Domain-separation label, so this digest can never be confused with a digest of the same
/// bytes taken for another purpose.
const LABEL: &[u8] = b"mcp-re-audit-v1/envelope";

/// `SHA-256(label || 0x00 || canonical bytes)`: what an event SAYS, independent of where a
/// transport put it.
///
/// Two deliveries of one event carry one digest. One identity carrying two digests is an
/// integrity conflict ([`super::EventBinding::recurrence_of`]), never a newer version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// The digest of `canonical`.
    pub(super) fn of(canonical: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(LABEL);
        hasher.update([0x00]);
        hasher.update(canonical);
        ContentDigest(hasher.finalize().into())
    }

    /// The thirty-two digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The label is part of the digest: the digest of no bytes is not SHA-256 of no bytes.
    /// Both values computed independently: `printf 'mcp-re-audit-v1/envelope\0' | shasum -a 256`
    /// and `printf '' | shasum -a 256`.
    #[test]
    fn the_digest_is_labelled() {
        let digest = ContentDigest::of(b"");
        assert_eq!(
            digest.to_string(),
            "10292f15c300080757eeec13fc30905972d3e91475b4e70cfffdab0615b5c17c"
        );
        assert_ne!(
            digest.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.as_bytes().len(), 32);
        assert_ne!(ContentDigest::of(b"a"), ContentDigest::of(b"b"));
    }
}
