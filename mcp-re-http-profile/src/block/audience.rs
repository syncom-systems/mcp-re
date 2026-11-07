// SPDX-License-Identifier: Apache-2.0
//! The MCP-RE audience tuple and its canonical, injective byte form and hash.

use mcp_re_core::b64url_encode;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::actor::field_escape;

/// The MCP-RE audience tuple — richer than `@target-uri` (v0.11 grill E-3).
/// It names the intended verifier identity AND the concrete target URI (plus an
/// optional route discriminator) so audience binding is not aliased by a shared
/// HTTP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceTuple {
    /// Intended verifier identity (mirrors the native envelope `audience`).
    pub audience_id: String,
    /// The absolute target URI the request is bound to (`@target-uri`).
    pub target_uri: String,
    /// Optional route/tenant discriminator for endpoints that multiplex
    /// several logical audiences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

impl AudienceTuple {
    /// Canonical byte serialization: the three ESCAPED slots joined by the unit
    /// separator `0x1F`, always three slots (empty route is an empty slot).
    ///
    /// Fixed arity alone does not make the encoding injective, because a separator
    /// INSIDE a field is indistinguishable from the join: these are
    /// serde-deserialized JSON strings, which carry any code point, so
    /// `("x", "y", Some("z\u{1f}"))` and `("x", "y\u{1f}z", Some(""))` produced one
    /// byte string and therefore one [`audience_hash`](Self::audience_hash). Each
    /// field is escaped through the same [`field_escape`] the `actor_id` join uses,
    /// which is reversible and leaves no `0x1F` in any slot: two tuples share bytes only when
    /// they differ solely by an absent versus an empty `route`, which are one slot by design.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let route = self.route.as_deref().unwrap_or("");
        let joined = format!(
            "{}\u{1f}{}\u{1f}{}",
            field_escape(&self.audience_id),
            field_escape(&self.target_uri),
            field_escape(route)
        );
        joined.into_bytes()
    }

    /// `base64url-no-pad(SHA-256(canonical audience tuple bytes))` — the
    /// `audience_hash` replay-key component.
    pub fn audience_hash(&self) -> String {
        b64url_encode(&Sha256::digest(self.canonical_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(audience_id: &str, target_uri: &str, route: Option<&str>) -> AudienceTuple {
        AudienceTuple {
            audience_id: audience_id.into(),
            target_uri: target_uri.into(),
            route: route.map(Into::into),
        }
    }

    #[test]
    fn audience_hash_is_deterministic_and_b64url() {
        let a = tuple("did:example:server", "https://mcp.example.com/mcp", None);
        assert_eq!(a.audience_hash(), a.audience_hash());
        assert!(!a.audience_hash().contains('='), "base64url no-pad");
        assert!(!a.audience_hash().contains(':'), "bare digest, no prefix");
    }

    #[test]
    fn different_audiences_on_one_endpoint_hash_differently() {
        let base = "https://mcp.example.com/mcp";
        let a = tuple("did:example:server-a", base, None);
        let b = tuple("did:example:server-b", base, None);
        // Same HTTP endpoint, different verifier identity -> different hash.
        assert_ne!(a.audience_hash(), b.audience_hash());
        // Route discriminator also separates.
        let c = AudienceTuple {
            route: Some("tenant-1".into()),
            ..a.clone()
        };
        assert_ne!(a.audience_hash(), c.audience_hash());
    }

    #[test]
    fn separator_cannot_be_forged_across_fields() {
        // audience_id "x" + target "y" must differ from audience_id "x\u{1f}y".
        let a = tuple("x", "y", None);
        let b = tuple("x\u{1f}y", "", None);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// Fixed arity does not rescue the join on its own: a separator carried INSIDE a
    /// field is indistinguishable from the join that follows it. These pairs are
    /// distinct audiences that shared one `audience_hash` — one replay-key audience
    /// slot and one delegated-credential scope value for two different MCP audiences.
    #[test]
    fn a_separator_inside_a_field_does_not_collapse_two_audiences() {
        let collisions = [
            (
                tuple("x", "y", Some("z\u{1f}")),
                tuple("x", "y\u{1f}z", Some("")),
            ),
            (
                tuple("a\u{1f}b", "c", Some("d")),
                tuple("a", "b\u{1f}c", Some("d")),
            ),
        ];
        for (a, b) in collisions {
            assert_ne!(a, b, "the pair must really be two different tuples");
            assert_ne!(
                a.canonical_bytes(),
                b.canonical_bytes(),
                "{a:?} and {b:?} must not share one canonical encoding"
            );
            assert_ne!(a.audience_hash(), b.audience_hash());
        }
    }

    /// The escape must be reversible, or it would trade one collision for another:
    /// a field containing the escape marker must not collide with the escaped form
    /// of a different field.
    #[test]
    fn the_escape_marker_itself_does_not_create_a_collision() {
        let a = tuple("%1F", "t", None);
        let b = tuple("\u{1f}", "t", None);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(a.audience_hash(), b.audience_hash());
    }

    #[test]
    fn an_absent_route_and_an_empty_route_are_one_audience_slot() {
        let a = tuple("did:example:server", "https://mcp.example.com/mcp", None);
        let b = tuple(
            "did:example:server",
            "https://mcp.example.com/mcp",
            Some(""),
        );
        assert_ne!(a, b);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.audience_hash(), b.audience_hash());
    }
}
