// SPDX-License-Identifier: Apache-2.0
//! What a KMS endpoint's host and port MEAN — whether the text names the machine a reader
//! thinks it names, and the port a URL parser will actually reach.
//!
//! Policy over the pieces [`super::authority`] divided. Both checks hold one agreement: the
//! host and port the text reads as are the host and port a URL parser connects to.

use std::str::FromStr;

use crate::deployment_request::RedactedLocator;

/// Whether the host names the machine a reader thinks it names.
///
/// A bracketed host's contents must parse as an address — `[foo-bar]` and `[gggg::1]` are
/// bracket-shaped but are not IPv6 literals, and a URL parser refuses both. Admitting
/// them here would only move the failure to the first request.
///
/// The unbracketed host is held to letters, digits, `.`, `-` and `_`. That is every
/// character a URL parser reads back as the text itself AND that a resolver can answer
/// for: `_` is admitted because internal DNS names carry it and `url` reads it verbatim.
/// The remaining printable ASCII that `url` also reads verbatim — ``! " $ & ' ( ) * + , ; =
/// ` { } ~`` — is refused as defence in depth: none of it can appear in a name
/// `getaddrinfo` will resolve, so refusing it costs no reachable endpoint. Everything else
/// is refused because a parser does NOT read it as written: `# / ? @ \` move the host,
/// and `% : < > [ ] ^ |` make `url` fail outright.
pub(super) fn check_host(host: &str, locator: &RedactedLocator) -> Result<(), String> {
    if host.starts_with('[') && host.ends_with(']') {
        return check_bracketed(host, locator);
    }
    if host.is_empty() {
        return Err(format!("has no host: {locator}"));
    }
    if let Some(bad) = host
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        return Err(format!(
            "host {host:?} is not a literal name or IP address ({bad:?} is percent-, IDNA- \
             or separator-encoding, which a URL parser resolves to a DIFFERENT host than \
             the text reads, or a character no resolver can answer for): {locator}"
        ));
    }
    check_numeric_tail(host, locator)
}

fn check_bracketed(host: &str, locator: &RedactedLocator) -> Result<(), String> {
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if std::net::Ipv6Addr::from_str(literal).is_err() {
        return Err(format!(
            "host {host:?} is bracket-shaped but is not an IPv6 address, which a URL parser \
             refuses outright: {locator}"
        ));
    }
    Ok(())
}

/// A URL parser reads a host whose LAST label is a NUMBER as an IPv4 address rather
/// than a name, and then rewrites it: `0x7f.1`, `127.1` and `2130706433` all resolve
/// to 127.0.0.1, and `1.1` to 1.0.0.1. Character-legal, but the address reached is
/// not the text. So a host of that shape is admitted only when it already IS a plain
/// dotted quad, where the two agree. No DNS name is affected — a top-level label
/// cannot be all-numeric, and `url` errors on one that is.
fn check_numeric_tail(host: &str, locator: &RedactedLocator) -> Result<(), String> {
    let last_label = host
        .rsplit('.')
        .find(|label| !label.is_empty())
        .unwrap_or("");
    let read_as_an_address = last_label.chars().all(|c| c.is_ascii_digit())
        || last_label.starts_with("0x")
        || last_label.starts_with("0X");
    if read_as_an_address && std::net::Ipv4Addr::from_str(host).is_err() {
        return Err(format!(
            "host {host:?} ends in a number, so a URL parser reads it as an IPv4 ADDRESS \
             and rewrites it (0x7f.1 and 127.1 both become 127.0.0.1); write the dotted \
             quad the request will actually reach: {locator}"
        ));
    }
    Ok(())
}

/// Whether the port reached is the port written.
///
/// A TCP port is a u16. "all digits" is not the same rule: `:65536` and `:99999999` are
/// all digits, and `url::Url::parse` refuses both — so admitting them would be a genuine
/// disagreement about whether the endpoint is usable at all. A leading zero is refused for
/// the narrower reason that `:0443` parses to 443, making the text and the port reached
/// differ.
pub(super) fn check_port(port: &str, locator: &RedactedLocator) -> Result<(), String> {
    // Digits ONLY, checked before parsing: `u16::from_str` accepts a leading `+`, so
    // `:+443` would parse to 443 while `url::Url::parse` refuses it outright.
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "port {port:?} is not a number, and a URL parser refuses it outright: \
             {locator}"
        ));
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(format!(
            "port {port:?} has a leading zero, so the text and the port a URL parser \
             reads differ: {locator}"
        ));
    }
    if port.parse::<u16>().is_err() {
        return Err(format!(
            "port {port:?} is not a TCP port number (0-65535), and a URL parser refuses \
             it outright: {locator}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_host, check_port, RedactedLocator};

    /// A stand-in for the projected whole the predicates carry into their refusals. Each
    /// predicate is being asked about its OWN argument here; the rendered whole is a
    /// constant for every case, so one is shared rather than restated per call.
    fn locator() -> RedactedLocator {
        RedactedLocator::of("https://kms.example.com")
    }

    #[test]
    fn check_host_refuses_a_bracket_shaped_host_that_is_not_an_address() {
        assert!(check_host("[::1]", &locator()).is_ok());
        assert!(check_host("[foo-bar]", &locator()).is_err());
        assert!(check_host("[gggg::1]", &locator()).is_err());
    }

    #[test]
    fn check_host_refuses_a_host_a_parser_would_rewrite_to_a_different_address() {
        // The `127.1` half of the module invariant: character-legal, but the address
        // reached is not the text. A plain dotted quad is admitted because there the two
        // agree, and a name is admitted because a parser does not rewrite it.
        assert!(check_host("127.0.0.1", &locator()).is_ok());
        assert!(check_host("kms.example.internal", &locator()).is_ok());
        assert!(check_host("127.1", &locator()).is_err());
        assert!(check_host("0x7f.1", &locator()).is_err());
        assert!(check_host("2130706433", &locator()).is_err());
    }

    #[test]
    fn check_port_refuses_a_port_whose_text_and_value_differ() {
        // The `:0443` half of the same invariant.
        assert!(check_port("443", &locator()).is_ok());
        assert!(check_port("0", &locator()).is_ok());
        assert!(check_port("0443", &locator()).is_err());
        assert!(check_port("+443", &locator()).is_err());
        assert!(check_port("65536", &locator()).is_err());
        assert!(check_port("", &locator()).is_err());
    }
}
