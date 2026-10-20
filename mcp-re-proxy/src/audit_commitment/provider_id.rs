// SPDX-License-Identifier: Apache-2.0
//! The name a commitment provider is reported by.

/// The reserved name of the test-only reference authority. No provider can claim it:
/// [`ProviderId::new`] refuses it, so a startup line naming it names the reference.
const RESERVED_REFERENCE: &str = "reference";

/// A commitment provider's name, as the startup posture line and the shutdown report print
/// it (ADR-MCPRE-070 §9).
///
/// `[a-z0-9][a-z0-9._-]{0,63}`: a name, never a locator, a credential or free text. The
/// grammar is what lets the posture line print it without leaking a provider's settings or
/// secrets into diagnostics — a URL, a token or a sentence does not parse. There is no
/// `From<String>`; the only constructor checks.
///
/// `pub` because a provider names itself through it (the [`super::CommitmentAuthority`]
/// contract); a name grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    /// `name`, or `None` when it is outside the grammar or is the reserved reference name.
    pub fn new(name: &str) -> Option<Self> {
        (is_grammatical(name) && name != RESERVED_REFERENCE).then(|| ProviderId(name.to_owned()))
    }

    /// The reference authority's name. Test-only flavors: no deployable build can name it.
    #[cfg(any(test, feature = "audit_commitment_reference"))]
    pub(super) fn reference() -> Self {
        ProviderId(RESERVED_REFERENCE.to_owned())
    }

    /// Whether this is the reserved reference name (ADR-MCPRE-070 §9).
    pub(super) fn is_reference(&self) -> bool {
        self.0 == RESERVED_REFERENCE
    }

    /// The name, as printed.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
fn is_grammatical(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".-_".contains(c));
    first_ok && rest_ok && name.len() <= 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_in_the_grammar_is_accepted_verbatim() {
        for name in ["journal", "acme-kafka.v2", "0", "a_b"] {
            assert_eq!(
                ProviderId::new(name).map(|id| id.to_string()),
                Some(name.into())
            );
        }
        assert!(ProviderId::new(&"a".repeat(64)).is_some());
    }

    /// A locator, a credential or a sentence is not a name, so none of them can reach a
    /// startup line through this type.
    #[test]
    fn anything_outside_the_grammar_is_refused() {
        for name in [
            "",
            "Journal",
            "-lead",
            "redis://user:SECRET@host:6379",
            "has space",
            "tok=SECRET",
            "a/b",
            "é",
        ] {
            assert!(ProviderId::new(name).is_none(), "{name:?}");
        }
        assert!(ProviderId::new(&"a".repeat(65)).is_none());
    }

    /// No provider can name itself the reference authority (ADR-MCPRE-070 §9).
    #[test]
    fn the_reference_name_is_reserved() {
        assert!(ProviderId::new("reference").is_none());
        assert!(ProviderId::reference().is_reference());
        assert!(!ProviderId::new("journal").expect("legal").is_reference());
    }
}
