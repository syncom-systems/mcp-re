// SPDX-License-Identifier: Apache-2.0
//! The locator projection — see the crate root for the authority this implements.

use std::fmt;

/// What is rendered when the input cannot be decomposed at all: the input is not echoed,
/// so nothing about its contents — including whether it held a credential — is published.
const UNPARSEABLE: &str = "<unparseable>";

/// What is rendered when the input is a reference with no authority component. It names
/// the shape, and, like [`UNPARSEABLE`], says nothing about the contents.
const NO_AUTHORITY: &str = "<no-authority>";

/// One operator-configured locator as an operator may see it: scheme, host and port, with
/// every credential-bearing component removed and its removal reported.
///
/// A shape this cannot decompose is NAMED rather than echoed, because echoing is exactly
/// what must not happen to an unparsed string — a credential-bearing value that fails a
/// deployment's own `://` shape check (`mats:hunter2@host:6379`) reaches the violation
/// message by that route and no other.
pub struct RedactedLocator(String);

impl RedactedLocator {
    /// Render `raw` for a human-readable line. Infallible on purpose: this is a projection
    /// for human eyes, and a locator a deployment REFUSES must still be nameable in the
    /// message an operator reads while diagnosing that refusal.
    pub fn of(raw: &str) -> Self {
        Self(project(raw))
    }
}

impl fmt::Display for RedactedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The projection itself: scheme and routing coordinates, plus what was removed.
///
/// Fail-closed at every step — each `return` below names a shape rather than describing
/// it, so no branch can reach the rendered text carrying input.
fn project(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        // A path-absolute reference has no authority and is a recognisable shape; anything
        // else without a scheme delimiter is exactly the credential-bearing form
        // (`user:pass@host:port`) that a locator-shape refusal fires on.
        if raw.starts_with('/') {
            return NO_AUTHORITY.to_string();
        }
        return UNPARSEABLE.to_string();
    };
    if !Scheme(scheme).is_valid() {
        return UNPARSEABLE.to_string();
    }
    // RFC 3986: the authority ends at the first `/`, `?` or `#`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return NO_AUTHORITY.to_string();
    }
    // The userinfo runs to the LAST `@`, which is where a URL parser reads the host from.
    let (userinfo_present, host_port) = match authority.rsplit_once('@') {
        Some((_userinfo, after_at)) => (true, after_at),
        None => (false, authority),
    };
    let Some(coordinates) = HostPort(host_port).coordinates() else {
        return UNPARSEABLE.to_string();
    };
    // `authority` is a prefix of `rest` by construction, so this is a char boundary.
    let tail = rest.get(authority.len()..).unwrap_or("");
    format!(
        "{scheme}://{coordinates}{}",
        Tail(tail).removed(userinfo_present)
    )
}

/// A candidate RFC 3986 scheme, the only form echoed verbatim.
struct Scheme<'a>(&'a str);

impl Scheme<'_> {
    fn is_valid(&self) -> bool {
        let mut chars = self.0.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    }
}

/// The `host[:port]` of an authority with its userinfo already removed.
///
/// The host is the one component echoed, so it is held to the characters a name or an
/// address is written with. Anything else — percent-encoding, a separator a parser
/// resolves differently, a non-numeric port — is not confidently a routing coordinate,
/// and the caller names the whole locator instead of publishing it.
struct HostPort<'a>(&'a str);

impl HostPort<'_> {
    /// The `host[:port]` a request would reach, or `None` when it cannot be established.
    fn coordinates(&self) -> Option<String> {
        match self.0.strip_prefix('[') {
            Some(after_bracket) => Self::bracketed(after_bracket),
            None => self.named(),
        }
    }

    /// `[literal]` and its optional port, where `after_bracket` follows the opening bracket.
    fn bracketed(after_bracket: &str) -> Option<String> {
        let (literal, after) = after_bracket.split_once(']')?;
        let ipv6 = !literal.is_empty()
            && literal
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        if !ipv6 {
            return None;
        }
        Some(format!("[{literal}]{}", PortSuffix(after).rendered()?))
    }

    /// A host name or address and its optional port.
    fn named(&self) -> Option<String> {
        let (host, port) = match self.0.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (self.0, None),
        };
        if !HostName(host).is_valid() {
            return None;
        }
        match port {
            None => Some(host.to_string()),
            Some(port) if Port(port).is_valid() => Some(format!("{host}:{port}")),
            Some(_) => None,
        }
    }
}

/// A candidate host name or address.
struct HostName<'a>(&'a str);

impl HostName<'_> {
    /// Whether the host is written with only the characters a name or an address uses.
    fn is_valid(&self) -> bool {
        !self.0.is_empty()
            && self
                .0
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    }
}

/// The text after an IPv6 literal's closing bracket.
struct PortSuffix<'a>(&'a str);

impl PortSuffix<'_> {
    /// The suffix as a renderable `:port`, empty when there is none, `None` when malformed.
    fn rendered(&self) -> Option<String> {
        if self.0.is_empty() {
            return Some(String::new());
        }
        let port = self.0.strip_prefix(':')?;
        Port(port).is_valid().then(|| format!(":{port}"))
    }
}

/// A candidate TCP port.
struct Port<'a>(&'a str);

impl Port<'_> {
    /// Whether the port is written as itself: digits only, and in range.
    fn is_valid(&self) -> bool {
        !self.0.is_empty()
            && self.0.chars().all(|c| c.is_ascii_digit())
            && self.0.parse::<u16>().is_ok()
    }
}

/// Everything after the authority: path, query and fragment.
///
/// A path made only of `/` carried nothing, so it is not reported as removed; every other
/// non-empty path was material an operator configured and must be told is missing from the
/// rendered line.
struct Tail<'a>(&'a str);

impl Tail<'_> {
    /// What was removed, in a stable order, naming each component and never its contents.
    fn removed(&self, userinfo_present: bool) -> String {
        let (before_fragment, fragment) = match self.0.split_once('#') {
            Some((before, fragment)) => (before, Some(fragment)),
            None => (self.0, None),
        };
        let (path, query) = match before_fragment.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (before_fragment, None),
        };
        let mut components = Vec::new();
        if userinfo_present {
            components.push("userinfo removed");
        }
        if path.chars().any(|c| c != '/') {
            components.push("path removed");
        }
        if query.is_some() {
            components.push("query removed");
        }
        if fragment.is_some() {
            components.push("fragment removed");
        }
        if components.is_empty() {
            return String::new();
        }
        format!(" ({})", components.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOAD-BEARING: the reason this type exists. A password in the authority must not
    /// reach the rendered text under any component of the projection.
    #[test]
    fn userinfo_never_reaches_the_rendered_locator() {
        let rendered =
            RedactedLocator::of("https://alice:hunter2@backend.internal/mcp").to_string();
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("alice"),
            "credentials survived the projection: {rendered}"
        );
        assert_eq!(
            rendered,
            "https://backend.internal (userinfo removed, path removed)"
        );
    }

    /// The second half of the same control: not one component of the configured string may
    /// be reassembled from the line, and the complete string may not appear in it.
    #[test]
    fn the_complete_configured_locator_never_appears_in_the_rendering() {
        const CONFIGURED: &str = "https://alice:hunter2@backend.internal/mcp";
        let rendered = RedactedLocator::of(CONFIGURED).to_string();
        assert!(
            !rendered.contains(CONFIGURED),
            "the complete configured locator was echoed: {rendered}"
        );
        assert!(
            !rendered.contains('@') && !rendered.contains("/mcp"),
            "a credential-bearing component survived: {rendered}"
        );
    }

    /// LOAD-BEARING: a credential does not have to sit in the userinfo. A token in query
    /// material is a configured credential too, and nothing here proves a query safe.
    #[test]
    fn a_credential_in_query_material_never_reaches_the_rendering() {
        let rendered = RedactedLocator::of("http://h:2379/?token=s3cr3t").to_string();
        assert!(
            !rendered.contains("s3cr3t") && !rendered.contains("token"),
            "query material reached the diagnostic: {rendered}"
        );
        assert_eq!(rendered, "http://h:2379 (query removed)");
    }

    /// LOAD-BEARING: the path is credential-bearing material too — a bearer token carried
    /// as a path segment is exactly the shape a rendered path publishes.
    #[test]
    fn a_path_is_removed_and_its_removal_is_reported() {
        let rendered = RedactedLocator::of("https://vault.internal/v1/token/s3cr3t").to_string();
        assert!(
            !rendered.contains("s3cr3t") && !rendered.contains("token"),
            "a path segment reached the diagnostic: {rendered}"
        );
        assert_eq!(rendered, "https://vault.internal (path removed)");
    }

    /// The markers report WHICH component was removed, never WHAT it held — so a locator
    /// whose removed components are conspicuous secrets renders the same markers as one
    /// whose removed components are ordinary.
    #[test]
    fn the_removal_markers_do_not_carry_what_was_removed() {
        let secret =
            RedactedLocator::of("https://u:p@h:8443/hunter2?k=hunter2#hunter2").to_string();
        assert!(
            !secret.contains("hunter2"),
            "a marker carried its contents: {secret}"
        );
        assert_eq!(
            secret,
            "https://h:8443 (userinfo removed, path removed, query removed, fragment removed)"
        );
        let ordinary = RedactedLocator::of("https://u:p@h:8443/mcp?a=b#c").to_string();
        assert_eq!(secret, ordinary, "the markers must not vary with contents");
    }

    /// LOAD-BEARING: this is the exact leak. A credential-bearing value with no `://` is
    /// precisely what every locator-shape violation fires on, so the rendering of THIS
    /// shape is what stands between a typo and a password in the startup diagnostic. It
    /// must be named, never echoed.
    #[test]
    fn a_scheme_less_credential_bearing_locator_is_named_not_echoed() {
        let rendered = RedactedLocator::of("mats:hunter2@host:6379").to_string();
        assert!(
            !rendered.contains("hunter2"),
            "the password reached the diagnostic: {rendered}"
        );
        assert!(
            !rendered.contains('@'),
            "no userinfo delimiter may survive: {rendered}"
        );
        assert_eq!(rendered, "<unparseable>");
    }

    /// POSITIVE CONTROL: the projection removed material, not usefulness. A normal
    /// credential-free locator still shows the coordinates an operator routes by.
    #[test]
    fn a_credential_free_locator_renders_without_the_marker() {
        assert_eq!(
            RedactedLocator::of("redis://redis.internal:6379").to_string(),
            "redis://redis.internal:6379"
        );
        assert_eq!(
            RedactedLocator::of("http://127.0.0.1:8621").to_string(),
            "http://127.0.0.1:8621"
        );
        assert_eq!(
            RedactedLocator::of("https://backend.internal/").to_string(),
            "https://backend.internal"
        );
        assert_eq!(
            RedactedLocator::of("http://[::1]:2379").to_string(),
            "http://[::1]:2379"
        );
    }

    #[test]
    fn a_shape_the_projection_cannot_decompose_is_named() {
        for named in [
            "not a url at all",
            "",
            "://backend.internal",
            "1https://backend.internal",
            "https://back end.internal",
            "https://backend.internal:80443",
            "https://backend.internal:htt",
            "https://[gggg::1]",
            "https://[::1junk",
        ] {
            assert_eq!(
                RedactedLocator::of(named).to_string(),
                "<unparseable>",
                "{named:?} must be named, not echoed"
            );
        }
        assert_eq!(RedactedLocator::of("/mcp").to_string(), "<no-authority>");
        assert_eq!(
            RedactedLocator::of("https:///mcp").to_string(),
            "<no-authority>"
        );
    }
}
