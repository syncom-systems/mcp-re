// SPDX-License-Identifier: Apache-2.0
//! The components of a locator's authority and tail, each judged by what it is written with.

/// A candidate RFC 3986 scheme, the only form echoed verbatim.
pub(crate) struct Scheme<'a>(pub(crate) &'a str);

impl Scheme<'_> {
    pub(crate) fn is_valid(&self) -> bool {
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
pub(crate) struct HostPort<'a>(pub(crate) &'a str);

impl HostPort<'_> {
    /// The `host[:port]` a request would reach, or `None` when it cannot be established.
    pub(crate) fn coordinates(&self) -> Option<String> {
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
pub(crate) struct Tail<'a>(pub(crate) &'a str);

impl Tail<'_> {
    /// What was removed, in a stable order, naming each component and never its contents.
    pub(crate) fn removed(&self, userinfo_present: bool) -> String {
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
