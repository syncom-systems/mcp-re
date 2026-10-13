// SPDX-License-Identifier: Apache-2.0
//! The root issuer a caller pins, and the trust anchor it becomes.
//!
//! Both verification entry points anchor on one pinned root issuer. The anchor is the
//! audited core's `TrustedIssuerSet`, evaluated at the caller's `now`: a root the caller
//! declares retired resolves through its overlap deadline and not after it, by the core's
//! own lifecycle rule rather than one restated here.

use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::TrustedIssuerSet;
use mcp_re_core::VerificationKey;

use crate::BindingError;
use crate::IssuerField;

/// The root issuer a caller pins. With `retired_until` the root is RETIRED and trusted only
/// while `now <= retired_until`; without it, CURRENT.
#[derive(Debug, Clone)]
pub struct PinnedIssuer {
    pub key_id: String,
    pub pubkey_b64url: String,
    pub role: String,
    pub trust_domain: String,
    pub subject: String,
    pub retired_until: Option<i64>,
}

impl PinnedIssuer {
    /// The trusted root-issuer anchor for the Response slot. The credential chains to this
    /// issuer, whose role, trust domain and subject must equal the server signer the
    /// credential names; the delegated key itself is authorized by the credential and is
    /// never enrolled.
    ///
    /// Refuses an identity with an empty field, naming it, before reading the key: the core
    /// compares the pinned principal with the credential's by equality, so an empty pin
    /// would match an empty claim.
    pub fn anchor(self) -> Result<TrustedIssuerSet, BindingError> {
        for (field, value) in [
            (IssuerField::KeyId, &self.key_id),
            (IssuerField::Role, &self.role),
            (IssuerField::TrustDomain, &self.trust_domain),
            (IssuerField::Subject, &self.subject),
        ] {
            if value.trim().is_empty() {
                return Err(BindingError::EmptyIssuerField(field));
            }
        }
        let key = VerificationKey::from_b64url(&self.pubkey_b64url)
            .map_err(|_| BindingError::Local("invalid issuer public key".into()))?;
        let root = ResolvedActor {
            identity: ActorIdentity {
                role: self.role,
                trust_domain: self.trust_domain,
                subject: self.subject,
                keyid: self.key_id,
            },
            verification_key: key,
            slot: SignerSlot::Response,
        };
        Ok(match self.retired_until {
            Some(deadline) => TrustedIssuerSet::new().with_retired(root, deadline),
            None => TrustedIssuerSet::new().with_current(root),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PinnedIssuer;
    use crate::BindingError;
    use crate::IssuerField;
    use mcp_re_client_core::DelegatedResponseTrust;
    use mcp_re_client_core::ResolverOutcome;
    use mcp_re_client_core::SignerSlot;
    use mcp_re_client_core::TrustedIssuerSet;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_000;

    type Setter = fn(&mut PinnedIssuer, String);

    fn issuer(retired_until: Option<i64>) -> PinnedIssuer {
        PinnedIssuer {
            key_id: "root-1".to_owned(),
            pubkey_b64url: SigningKey::from_seed_bytes(&[7u8; 32])
                .public_key()
                .to_b64url(),
            role: "server".to_owned(),
            trust_domain: "example.com".to_owned(),
            subject: "did:example:server-1".to_owned(),
            retired_until,
        }
    }

    fn resolves(set: &TrustedIssuerSet, now: i64) -> bool {
        matches!(
            set.resolve_issuer("root-1", SignerSlot::Response, now),
            ResolverOutcome::Resolved(_)
        )
    }

    #[test]
    fn an_empty_issuer_field_is_refused_by_name() {
        let named: [(IssuerField, Setter); 4] = [
            (IssuerField::KeyId, |i, v| i.key_id = v),
            (IssuerField::Role, |i, v| i.role = v),
            (IssuerField::TrustDomain, |i, v| i.trust_domain = v),
            (IssuerField::Subject, |i, v| i.subject = v),
        ];
        for (field, set) in named {
            for blank in ["", "  "] {
                let mut pinned = issuer(None);
                set(&mut pinned, blank.to_owned());
                assert_eq!(
                    pinned.anchor().err(),
                    Some(BindingError::EmptyIssuerField(field)),
                    "{field:?} = {blank:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_field_is_named_before_an_unreadable_key() {
        let mut pinned = issuer(None);
        pinned.pubkey_b64url = "!".to_owned();
        assert_eq!(
            pinned.clone().anchor().err(),
            Some(BindingError::Local("invalid issuer public key".into()))
        );
        pinned.role = String::new();
        assert_eq!(
            pinned.anchor().err(),
            Some(BindingError::EmptyIssuerField(IssuerField::Role))
        );
    }

    #[test]
    fn a_retired_root_resolves_through_its_deadline_and_not_after() {
        let retired = issuer(Some(NOW)).anchor().expect("a retired root builds");
        assert!(resolves(&retired, NOW));
        assert!(!resolves(&retired, NOW + 1));
        let current = issuer(None).anchor().expect("a current root builds");
        assert!(resolves(&current, NOW + 1_000_000));
    }
}
