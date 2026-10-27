// SPDX-License-Identifier: Apache-2.0
//! The configured RFC 9421 `@target-uri`, as an owned value whose shape is a construction
//! fact.
//!
//! ADR-MCPRE-058 §8.3. Two mechanisms read the configured target, and they need different
//! things from it:
//!
//! ```text
//!                       one absolute target
//!                              |
//!                +-------------+-------------+
//!                v                           v
//!     signature base + audience       arrival-path check
//!     (`@target-uri`, the whole URI)  (its origin form only)
//! ```
//!
//! The verifier covers the operator's asserted target rather than the received line, because
//! a proxy behind TLS termination cannot see the external URI. What makes that assertion
//! checkable is the origin form: the path and query this process CAN see, compared by
//! `async_serve` against the one each request arrived at. That comparison has an answer only
//! for an ABSOLUTE target, so a target with no `://` cannot be held here at all: the check is
//! never asked of a value it cannot answer.

use crate::deployment_request::DeploymentRequest;

/// An absolute `@target-uri` and its origin form.
///
/// The representation is private to this module and [`RequestTarget::new`] performs the
/// check, so possessing one IS the statement that the arrival-path check is answerable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    uri: String,
    origin_form: String,
}

impl RequestTarget {
    /// The only constructor, and it performs the check: an empty or scheme-less target is
    /// refused with the diagnostic an operator reads.
    ///
    /// Public for the reason [`super::FreshnessWindow::new`] is: an embedder that builds
    /// `ServerOptions` itself gets the same guarantee the classifier gets, not a way around it.
    pub fn new(uri: &str) -> Result<Self, String> {
        if uri.trim().is_empty() {
            return Err(
                "--target-uri must not be empty: an empty target makes the audience/target \
                 binding a tautology (both sides compare equal) instead of binding this \
                 deployment's dispatch boundary"
                    .to_string(),
            );
        }
        let Some((_scheme, authority)) = uri.split_once("://") else {
            return Err(format!(
                "--target-uri {} is not an absolute URI: it must be \
                 <scheme>://<authority><path> (e.g. https://proxy.internal:8600/mcp). \
                 A scheme-less target leaves the request-target reconstruction check \
                 nothing to compare, so an ingress fanning several paths into one process \
                 could not be told apart from one route",
                crate::deployment_request::RedactedLocator::of(uri)
            ));
        };
        let origin_form = match authority.find('/') {
            Some(offset) => authority.get(offset..).unwrap_or("/").to_owned(),
            None => "/".to_owned(),
        };
        Ok(Self {
            uri: uri.to_owned(),
            origin_form,
        })
    }

    /// The whole configured URI: the value the signature base covers as `@target-uri` and
    /// the audience tuple carries.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// The path and query a request must have arrived at for the asserted target to be a
    /// reconstruction of it. `/` for a target with no path.
    pub fn origin_form(&self) -> &str {
        &self.origin_form
    }
}

/// The deployment's request target, or the refusal explaining why it has none.
pub(in crate::config_state) fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<RequestTarget>, Vec<String>) {
    match RequestTarget::new(&config.target_uri) {
        Ok(target) => (Some(target), Vec::new()),
        Err(refusal) => (None, vec![refusal]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes the arrival-path check cannot answer are not constructible, and each
    /// refusal names the flag.
    #[test]
    fn a_target_the_reconstruction_check_cannot_answer_is_unconstructible() {
        for absolute in [
            "https://proxy.internal:8600/mcp",
            "http://127.0.0.1:8600/",
            "https://proxy.internal",
        ] {
            assert!(
                RequestTarget::new(absolute).is_ok(),
                "an absolute target is the supported shape: {absolute}"
            );
        }
        for unusable in [
            "",
            "   ",
            "/mcp",
            "proxy.internal:8600/mcp",
            "proxy.internal",
        ] {
            let refusal = RequestTarget::new(unusable)
                .expect_err("a target with no origin form must not be constructible");
            assert!(
                refusal.contains("--target-uri"),
                "the refusal must name the flag, got: {refusal}"
            );
        }
    }

    /// A credential-bearing typo is scheme-less; the refusal names the target rather than
    /// echoing it.
    #[test]
    fn the_target_uri_refusal_does_not_echo_a_credential() {
        let refusal = RequestTarget::new("mats:hunter2@proxy.internal:8600")
            .expect_err("a scheme-less target is refused");
        assert!(
            !refusal.contains("hunter2"),
            "the password reached the diagnostic: {refusal}"
        );
        assert!(
            refusal.contains("--target-uri"),
            "the refusal must still name the flag: {refusal}"
        );
    }

    /// The origin form is the path and query, and `/` where the target names no path.
    #[test]
    fn the_origin_form_is_the_path_and_query() {
        for (uri, origin) in [
            ("https://mcp.example.com/mcp?route=a", "/mcp?route=a"),
            ("https://mcp.example.com/", "/"),
            ("https://mcp.example.com", "/"),
        ] {
            let target = RequestTarget::new(uri).expect("absolute");
            assert_eq!(target.origin_form(), origin, "{uri}");
            assert_eq!(target.as_str(), uri);
        }
    }

    /// The classifier refuses exactly what construction refuses, so the validation boundary
    /// and an embedder are held to one rule.
    #[test]
    fn the_classifier_refuses_what_construction_refuses() {
        let mut config = crate::config_state::test_support::legal_config();
        config.target_uri = "proxy.internal/mcp".to_owned();
        let (state, refusals) = classify_and_validate(&config);
        assert!(state.is_none());
        assert_eq!(refusals.len(), 1);
        config.target_uri = "https://proxy.internal/mcp".to_owned();
        let (state, refusals) = classify_and_validate(&config);
        assert_eq!(
            state.map(|t| t.origin_form().to_owned()),
            Some("/mcp".to_owned())
        );
        assert!(refusals.is_empty());
    }
}
