// SPDX-License-Identifier: Apache-2.0
//! The resolved signing actor and the trust seam's answer for it: the identity pinned for
//! replay keys and audit (`actor_id`), the slot a key is trusted for, and the resolver
//! outcome that distinguishes an unknown keyid from an unavailable store.

use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "verify")]
use verus_builtin_macros::verus_verify;

/// The resolved signing-actor identity. Built by the verifier from what the
/// TrustResolver returned for the presented keyid — role and trusted key
/// identity, never the raw keyid alone (MCPRE-93/94 pin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorIdentity {
    /// Trust role the resolver assigned (e.g. `host`, `server`, `client`).
    pub role: String,
    /// Trust domain the subject belongs to.
    pub trust_domain: String,
    /// Resolved subject identity (e.g. a DID or service id — may itself contain
    /// `:`, which is why components are escaped before joining).
    pub subject: String,
    /// The RFC 9421 keyid the signature was verified under.
    pub keyid: String,
}

impl ActorIdentity {
    /// The canonical, injective `actor_id` string used as a replay-key
    /// component. Each field is escaped (`%`→`%25`, `:`→`%3A`) before the
    /// `role:trust_domain:subject:keyid` join, so distinct identities never
    /// collapse to the same key even when a subject contains colons.
    // ADR-MCPRE-059 ASM-0021: opaque to the continuation theorem, with no `ensures`. The
    // replay key's injectivity is its own property and its own future unit; nothing in the
    // unbypassability theorem depends on what this string is.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    pub fn actor_id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            field_escape(&self.role),
            field_escape(&self.trust_domain),
            field_escape(&self.subject),
            field_escape(&self.keyid),
        )
    }
}

/// Escape a single actor-id component so `:` joins stay unambiguous. `%` first
/// (so the escape is reversible), then `:`.
pub(super) fn field_escape(s: &str) -> String {
    // `%` first (so its own escape is not re-escaped), then EVERY separator any
    // consumer of this string uses. `:` joins the actor-id fields here; U+001F joins
    // the HTTP replay-key components downstream, and leaving it unescaped meant the
    // injectivity that key's construction ASSERTS was not enforced — an actor id
    // containing U+001F could produce the same joined key as a different
    // (actor, audience, nonce) triple.
    s.replace('%', "%25")
        .replace(':', "%3A")
        .replace('\u{1F}', "%1F")
}

/// The signing slot a keyid is resolved FOR. Passed INTO the trust seam so
/// role authorization is a decision of trust resolution, never inferred from a
/// role string after the fact (MCPRE-100): a key may be cryptographically valid
/// yet not trusted to sign in this slot, and that must fail
/// `actor_binding_failed` exactly like an unknown keyid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerSlot {
    /// The client/request-signer slot — [`crate::verify_request`].
    Request,
    /// The server/response-signer slot — [`crate::verify_response`],
    /// `verify_response_unbound`, and signed rejections.
    Response,
}

/// Trust-resolution output for a presented keyid: the resolved actor identity,
/// its verification key, and the slot the trust layer vouched this actor for.
/// The seam returns this ONLY when the key is trusted for the requested slot; a
/// wrong-slot key resolves to `None`, indistinguishable at the public error
/// layer from an unknown keyid (`mcp-re.actor_binding_failed`).
///
/// `keyid` is NOT `actor_id`: `actor_id` (see [`ActorIdentity::actor_id`]) is
/// the trust-resolution output that replay keys, response/body-block validation,
/// and audit consume — a keyid alone never introduces trust.
///
/// Not `PartialEq`/`Eq`: `VerificationKey` is opaque key material with no value
/// equality. Compare `identity` (or `actor_id()`) and `slot` instead.
#[derive(Debug, Clone)]
pub struct ResolvedActor {
    /// The resolved identity (role, trust domain, subject, keyid → `actor_id`).
    pub identity: ActorIdentity,
    /// The verification key trust resolution bound to this actor.
    pub verification_key: VerificationKey,
    /// The slot the trust layer authorized this actor for. The verifier asserts
    /// this equals the slot it requested — a typed defense-in-depth cross-check
    /// atop the seam's primary enforcement, never a role-string comparison.
    pub slot: SignerSlot,
}

/// What the trust seam answers with (C079).
///
/// The seam used to be `-> Option<ResolvedActor>`, which made a store OUTAGE and an
/// UNKNOWN KEYID the same observation. Both fail closed — that was never in doubt —
/// but they are different facts, and the verifier reported the outage as
/// `actor_binding_failed`, sending an operator to inspect the caller's credentials
/// during an incident in their own trust store. `mcp-re-core` has modelled the
/// distinction since the beginning (`TrustResolverError::Unavailable`); it simply could
/// not cross this seam, so `mcp-re.trust_resolver_unavailable` had no emission site.
///
/// `From<Option<ResolvedActor>>` is provided so a resolver with no notion of
/// unavailability — every in-process and test resolver — stays a one-line closure:
/// `None` means NOT TRUSTED, which is what it always meant.
#[derive(Debug, Clone)]
pub enum ResolverOutcome {
    /// The keyid resolves to this actor for the requested slot. Boxed so the
    /// negative outcomes do not each carry the resolved actor's footprint.
    Resolved(Box<ResolvedActor>),
    /// A definitive negative from a HEALTHY resolver: no such trusted binding.
    /// → `mcp-re.actor_binding_failed`.
    NotTrusted,
    /// The resolver could not answer (backing store unreachable, timeout). NOT a
    /// verdict about the key, and never a fallback to allow.
    /// → `mcp-re.trust_resolver_unavailable`.
    Unavailable,
}

impl ResolverOutcome {
    /// The resolved actor, collapsing both negative outcomes to `None`.
    ///
    /// Used where a downstream seam cannot yet express unavailability — currently the
    /// delegation credential's ROOT-key resolver, which is
    /// `Fn(&str) -> Option<VerificationKey>`. Collapsing there preserves today's
    /// fail-closed behaviour exactly; widening that seam too is follow-on work, and it
    /// is called out here rather than left as a silent narrowing.
    pub fn resolved(self) -> Option<ResolvedActor> {
        match self {
            ResolverOutcome::Resolved(actor) => Some(*actor),
            ResolverOutcome::NotTrusted | ResolverOutcome::Unavailable => None,
        }
    }
}

impl From<Option<ResolvedActor>> for ResolverOutcome {
    fn from(value: Option<ResolvedActor>) -> Self {
        match value {
            Some(actor) => ResolverOutcome::Resolved(Box::new(actor)),
            None => ResolverOutcome::NotTrusted,
        }
    }
}

impl ResolvedActor {
    /// The canonical `actor_id` of the resolved signer (delegates to
    /// [`ActorIdentity::actor_id`]).
    // ADR-MCPRE-059 ASM-0021: delegates to the identity form; opaque for the same reason.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    pub fn actor_id(&self) -> String {
        self.identity.actor_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subject: &str, keyid: &str) -> ActorIdentity {
        ActorIdentity {
            role: "r".into(),
            trust_domain: "d".into(),
            subject: subject.into(),
            keyid: keyid.into(),
        }
    }

    #[test]
    fn actor_id_is_deterministic_and_pinned() {
        let a = ActorIdentity {
            role: "host".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:host".into(),
            keyid: "client-key-1".into(),
        };
        // Golden: subject colons are escaped so the join stays unambiguous.
        assert_eq!(
            a.actor_id(),
            "host:example.com:did%3Aexample%3Ahost:client-key-1"
        );
        assert_eq!(a.actor_id(), a.actor_id());
    }

    #[test]
    fn actor_id_is_injective_across_colon_boundaries() {
        // Without escaping, ("a:b","c") and ("a","b:c") would collide.
        let x = identity("a:b", "c");
        let y = identity("a", "b:c");
        assert_ne!(x.actor_id(), y.actor_id());
    }
}
