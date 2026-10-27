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
//!
//! The rest of the shape is what makes the URI a request target rather than any string with
//! a `://` in it (RFC 9110 §4.2, RFC 9421 §2.2.2):
//!
//! - printable ASCII only: the value is a line of the signature base;
//! - scheme `http` or `https`, the only ones this proxy serves;
//! - a non-empty host, a port only of digits, and no userinfo — the URI is signed and
//!   audited, so a credential in it would be published by both;
//! - no fragment, which no request carries, so a target with one could never match an
//!   arrival.

use crate::deployment_request::{DeploymentRequest, RedactedLocator};

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
        if !uri.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(refusal(
                uri,
                "contains whitespace, a control character or non-ASCII; a request target \
                 is printable ASCII, with anything else percent-encoded",
            ));
        }
        let Some((scheme, rest)) = uri.split_once("://") else {
            return Err(format!(
                "--target-uri {} is not an absolute URI: it must be \
                 <scheme>://<authority><path> (e.g. https://proxy.internal:8600/mcp). \
                 A scheme-less target leaves the request-target reconstruction check \
                 nothing to compare, so an ingress fanning several paths into one process \
                 could not be told apart from one route",
                RedactedLocator::of(uri)
            ));
        };
        if !(scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")) {
            return Err(refusal(uri, "names a scheme other than http or https"));
        }
        if rest.contains('#') {
            return Err(refusal(
                uri,
                "carries a fragment, which no request target has, so no request could match it",
            ));
        }
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, origin) = rest.split_at(split);
        check_authority(uri, authority)?;
        let origin_form = match origin.chars().next() {
            Some('/') => origin.to_owned(),
            _ => format!("/{origin}"),
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

/// A refusal naming the flag and the redacted target, never the target itself.
fn refusal(uri: &str, why: &str) -> String {
    format!("--target-uri {} {why}", RedactedLocator::of(uri))
}

/// The authority is `host[:port]`: a host that is present, a port of digits, no userinfo.
fn check_authority(uri: &str, authority: &str) -> Result<(), String> {
    if authority.contains('@') {
        return Err(refusal(
            uri,
            "carries userinfo; the target is signed and audited, so a credential in it would \
             be published by both",
        ));
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some((literal, "")) => (literal, None),
            Some((literal, after)) => match after.strip_prefix(':') {
                Some(port) => (literal, Some(port)),
                None => return Err(refusal(uri, "has text after its IP-literal host")),
            },
            None => return Err(refusal(uri, "has an unterminated IP-literal host")),
        },
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err(refusal(uri, "names no host"));
    }
    if port.is_some_and(|p| !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()) {
        return Err(refusal(uri, "has a port that is not a TCP port number"));
    }
    Ok(())
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

    /// An absolute URI that is not an HTTP request target is refused, naming the flag: the
    /// scheme, host, port, fragment and character set each decide whether a request could
    /// ever arrive at it.
    #[test]
    fn a_target_that_is_not_an_http_request_target_is_unconstructible() {
        for target in [
            "HTTPS://proxy.internal/mcp",
            "http://proxy.internal:8600?route=a",
            "https://[::1]:8600/mcp",
            "https://[::1]",
            "https://proxy.internal:65535/mcp%20x",
        ] {
            assert!(
                RequestTarget::new(target).is_ok(),
                "an HTTP request target is the supported shape: {target}"
            );
        }
        for not_a_target in [
            "ftp://proxy.internal/mcp",
            "://proxy.internal/mcp",
            "https:///mcp",
            "https://?route=a",
            "https://:8600/mcp",
            "https://proxy.internal:http/mcp",
            "https://proxy.internal:/mcp",
            "https://proxy.internal:65536/mcp",
            "https://proxy.internal:+80/mcp",
            "https://[::1/mcp",
            "https://[::1]x/mcp",
            "https://proxy.internal/mcp#section",
            "https://proxy.internal/m cp",
            " https://proxy.internal/mcp",
            "https://proxy.internal/mcp\t",
            "https://proxy.internal/\u{e9}",
        ] {
            let refusal = RequestTarget::new(not_a_target)
                .expect_err("a value no request can arrive at must not be constructible");
            assert!(
                refusal.contains("--target-uri"),
                "the refusal must name the flag, got: {refusal}"
            );
        }
    }

    /// A credential in the authority is refused, and the refusal does not publish it.
    #[test]
    fn a_target_carrying_userinfo_is_refused_without_echoing_it() {
        let refusal = RequestTarget::new("https://mats:hunter2@proxy.internal:8600/mcp")
            .expect_err("userinfo in a signed, audited target is refused");
        assert!(refusal.contains("userinfo"), "{refusal}");
        assert!(
            !refusal.contains("hunter2") && !refusal.contains("mats:"),
            "the credential reached the diagnostic: {refusal}"
        );
    }

    /// The origin form is the path and query, and `/` where the target names no path.
    #[test]
    fn the_origin_form_is_the_path_and_query() {
        for (uri, origin) in [
            ("https://mcp.example.com/mcp?route=a", "/mcp?route=a"),
            ("https://mcp.example.com/", "/"),
            ("https://mcp.example.com", "/"),
            ("https://mcp.example.com?route=a", "/?route=a"),
            ("https://mcp.example.com?next=/mcp", "/?next=/mcp"),
            ("https://[::1]:8600/mcp", "/mcp"),
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
