// SPDX-License-Identifier: Apache-2.0
//! Whether an operator-supplied KMS/STS endpoint may be used at all.
//!
//! This is a security policy, not a parsing concern. The rule it answers — may this
//! endpoint carry the root-key trust bootstrap, and on GCP a live workload-identity
//! bearer token — has the same meaning whether the value arrived on a command line, in
//! a config a validation pass is checking, or as a public struct field an embedder set
//! before reaching a key-source constructor.
//!
//! It therefore owns the rule rather than any of those callers owning it. The command
//! line and the validation boundary CONSUME this decision; so do the AWS KMS, AWS STS
//! and GCP KMS key sources, which an embedder can reach without meeting a parser at
//! all. None of them depends on another to obtain it.
//!
//! # The invariant
//!
//! > An endpoint authority is accepted only when its literal human-readable
//! > representation and the machine interpretation used by the client agree. Alternate
//! > host and port spellings that change the effective authority are refused.
//!
//! One rule, several subordinate predicates. `127.1` (an alternate IP representation a
//! parser rewrites to `127.0.0.1`) and `:0443` (a port canonicalisation that reaches
//! 443) are the same threat: text that names one endpoint to a reader and another to
//! the client. They are enforced by [`check_host`] and [`check_port`] respectively,
//! because they are different predicates — not because they are different concerns.
//!
//! The reasoning lives here rather than being restated in each check, so that reviewing
//! the rule means reading one argument and then confirming each predicate enforces its
//! share of it.

use std::str::FromStr;

// The ONE operator-facing projection of a configured locator. Every refusal below names
// the endpoint through it and never as configured: these values are `--kms-endpoint`-class
// operator input, and a WELL-FORMED URL is exactly the shape that carries a credential.
use crate::deployment_request::RedactedLocator;

mod authority;
use authority::split_authority;

mod host;
use host::{check_host, check_port};

// The endpoint as a VALUE, and the credential egress it grants — the half of this rule
// that key sources hold rather than call. Gated with the two backends that make such a
// request; a build with neither has no credential to send.
#[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
mod endpoint;
#[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
pub(crate) use endpoint::KmsEndpoint;

/// The `host[:port]` a request to `value` will actually reach — or why `value` may not be
/// used as a KMS/STS endpoint at all.
///
/// These overrides carry the ROOT-KEY trust bootstrap: `getPublicKey` fetches the
/// `spki_der`/verify key that the verify-before-return guardrail is measured against, and
/// on GCP every request also carries a live workload-identity bearer token. An unvalidated
/// override therefore hands a replayable credential to whatever host is named and lets a
/// substituted endpoint supply an attacker-chosen root signing key that every local
/// fail-closed check then passes self-consistently.
///
/// So the authority must be a LITERAL `host[:port]` — text a URL parser reads the same way
/// a reader does. `ureq` parses a request URL as an `http::Uri` and connects to its
/// authority's host, which reads `https://cloudkms.googleapis.com@evil.example.com` as host
/// `evil.example.com` with the recognisable half demoted to userinfo, and reads
/// `http://localhost:80@evil.example.com` the same way — so userinfo (`@`) is refused, and
/// so is any host carrying percent- or IDNA-encoding or a separator a parser resolves
/// differently (`\`, a tab, a stray `%`), all of which name one host to a reader and
/// another to the parser. The port must be numeric.
///
/// Scheme: `https://` always; `http://` ONLY to loopback — decided from the host below,
/// i.e. AFTER userinfo has been refused, because `http://localhost:80@evil.example.com`
/// otherwise reads as loopback while the plaintext bearer token leaves the machine. The
/// loopback exception is what keeps the LocalStack / KMS-emulator lane working.
///
/// Applied at parse for a command line, at the validation boundary via
/// [`kms_endpoint_refusals`] for any config, and again at key-source construction
/// (`UreqGcpClient::new`, `aws_kms_keysource::authority_of`,
/// `WebIdentityConfig::from_env`), since the endpoint fields are public and an embedder
/// reaches key-source construction without meeting a parser.
pub(crate) fn kms_endpoint_authority(value: &str) -> Result<String, String> {
    let locator = RedactedLocator::of(value);
    let (plaintext, rest) = split_scheme(value, &locator)?;
    let authority = bare_authority(rest, &locator)?;
    let (host, port) = split_host_port(authority, &locator)?;
    if plaintext && !names_this_machine(host) {
        return Err(format!(
            "may only use http:// for a loopback emulator named by address (127.0.0.0/8 or \
             [::1], e.g. http://127.0.0.1:4566); got host {host:?}. A name such as `localhost` \
             is answered by the host's resolver, not by this rule. A plaintext endpoint \
             exfiltrates the KMS credential and lets a substituted host supply the root verify \
             key"
        ));
    }
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The scheme's plaintext-ness and the text after it.
fn split_scheme<'a>(value: &'a str, locator: &RedactedLocator) -> Result<(bool, &'a str), String> {
    if let Some(rest) = value.strip_prefix("https://") {
        Ok((false, rest))
    } else if let Some(rest) = value.strip_prefix("http://") {
        Ok((true, rest))
    } else {
        Err(format!(
            "must be an absolute https:// URL (got {locator}); this endpoint carries the \
             root-key trust bootstrap and, on GCP, a live bearer token"
        ))
    }
}

/// The authority of `rest` — or why `rest` carries more than a bare `host[:port]`.
///
/// RFC 3986: the authority ends at the first `/`, `?` or `#`. A URL parser may end it
/// EARLIER (a `\` is a path separator for http(s) URLs, and tab/CR/LF are stripped
/// before parsing), never later — so the host it picks is always inside this span, and
/// rejecting the span's contents rejects the parser's host too.
///
/// A query or fragment is not part of an endpoint, and it does not survive the way the
/// GCP client builds its URLs: `{base}/v1/{name}:asymmetricSign` on a base carrying `?`
/// puts the whole operation path inside the query string. A trailing PATH is allowed —
/// an emulator legitimately serves the API under one.
///
/// The userinfo refusal fires PRECISELY when a password is present, so it may name
/// neither the authority nor the value. The fact an operator needs is the EFFECTIVE
/// host — the text after the '@', where the request would actually go — and that the
/// userinfo was there at all. The projection reports exactly those two.
fn bare_authority<'a>(rest: &'a str, locator: &RedactedLocator) -> Result<&'a str, String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("has no host: {locator}"));
    }
    if let Some(bad) = rest.chars().find(|c| matches!(c, '?' | '#')) {
        return Err(format!(
            "must be a bare scheme://host[:port][/path] endpoint; {bad:?} in {locator} is a \
             query or fragment, which is not part of an authority and is not carried through \
             the per-operation URLs built from it"
        ));
    }
    if authority.contains('@') {
        return Err(format!(
            "carries userinfo, and a URL parser reads the host as the text AFTER the '@': \
             the request would reach {locator} rather than the endpoint this value appears \
             to name, sending the root-key bootstrap and, on GCP, a live bearer token there"
        ));
    }
    Ok(authority)
}

/// Does `host` provably name THIS machine, so a plaintext credential sent to it cannot
/// leave it?
///
/// Decided from the parsed address, not from a spelling, so the canonicalisations a URL
/// parser performs do not change the answer: `url` reads `[0:0:0:0:0:0:0:1]` as `[::1]`,
/// and every address in 127.0.0.0/8 is loopback under RFC 1122, not just `127.0.0.1`.
///
/// Only an ADDRESS answers. A name — `localhost` included — is whatever the host's resolver
/// returns for it, and this rule cannot see that, so a plaintext endpoint named by a name is
/// refused.
///
/// The IPv4 shorthands a URL parser also accepts — `127.1`, `0x7f.1` — are NOT recognised
/// here, so they are refused rather than admitted as loopback. That is the safe direction
/// (a refusal), and no operator writes an emulator endpoint that way.
fn names_this_machine(host: &str) -> bool {
    if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return std::net::Ipv6Addr::from_str(literal).is_ok_and(|address| address.is_loopback());
    }
    std::net::Ipv4Addr::from_str(host).is_ok_and(|address| address.is_loopback())
}

/// Split a `host[:port]` authority, refusing anything that is not a literal host.
///
/// The three steps below are the module invariant applied to the three places an
/// authority can diverge: where the host ends, what the host is, and what the port is.
fn split_host_port<'a>(
    authority: &'a str,
    locator: &RedactedLocator,
) -> Result<(&'a str, Option<&'a str>), String> {
    let (host, port) = split_authority(authority, locator)?;
    check_host(host, locator)?;
    if let Some(port) = port {
        check_port(port, locator)?;
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    /// LOAD-BEARING: the userinfo refusal fires PRECISELY when a password is present, so
    /// it is the one refusal in this rule that would otherwise print the secret twice —
    /// once in the authority and once in the whole value. What an operator needs is the
    /// EFFECTIVE host, the text after the '@' where the request would actually go, and
    /// that userinfo was configured at all. Neither of those is the secret.
    ///
    /// Driven through `kms_endpoint_authority` rather than through `KmsEndpoint`, which is
    /// compiled only with a KMS backend feature: this control must measure something in the
    /// DEFAULT lane.
    #[test]
    fn the_userinfo_refusal_names_the_effective_host_and_not_the_credential() {
        assert_refusal_hides_the_configured_value(Refusal {
            configured: "https://cloudkms.googleapis.com:ops@evil.example.com:8443",
            leaked: &["ops@", "cloudkms.googleapis.com"],
            reported: ("evil.example.com:8443", "userinfo removed"),
            why: "an endpoint carrying userinfo must be refused",
        });
    }

    /// The second branch, and the one that proves the substitution is not local to the
    /// userinfo case: a query-bearing endpoint is refused by a different clause, and that
    /// clause must not print the token the query carries either.
    #[test]
    fn the_query_refusal_names_neither_the_token_nor_the_configured_endpoint() {
        assert_refusal_hides_the_configured_value(Refusal {
            configured: "https://kms.example.com:8443/?access_token=hunter2",
            leaked: &["hunter2", "access_token"],
            reported: ("kms.example.com:8443", "query removed"),
            why: "an endpoint carrying a query must be refused",
        });
    }

    /// POSITIVE CONTROL for both: the rendering changed, not which endpoints are usable.
    /// A legitimate credential-free endpoint is still admitted, and still yields the
    /// authority a request reaches.
    #[test]
    fn a_legitimate_endpoint_is_still_admitted_after_the_substitution() {
        assert_eq!(
            super::kms_endpoint_authority("https://kms.us-east-1.amazonaws.com:8443")
                .expect("a plain https endpoint is admissible"),
            "kms.us-east-1.amazonaws.com:8443"
        );
    }

    /// The host allowlist is a deliberate line, so it is pinned character by character.
    ///
    /// `_` is ADMITTED: internal DNS names carry it and `url::Url::parse` reads it back as
    /// the text itself, so refusing it would have been pure capability loss. The other
    /// printable ASCII `url` also reads verbatim is refused as defence in depth — none of
    /// it can appear in a name a resolver will answer for, so no reachable endpoint is
    /// lost. Measured against url 2.5.8, the crate ureq 2.12.1 links.
    #[test]
    fn the_host_allowlist_is_exactly_the_characters_a_resolver_can_answer_for() {
        assert!(
            super::kms_endpoint_authority("https://kms_internal.example:8443").is_ok(),
            "an underscore is read verbatim by a URL parser and appears in internal DNS names"
        );
        assert!(
            super::kms_endpoint_authority("http://kms_local:4566").is_err(),
            "but the loopback rule still applies to it"
        );
        // Refused, and url reads each of these VERBATIM — a named, accepted capability
        // loss, not an oversight: none can appear in a name `getaddrinfo` resolves.
        for c in [
            '!', '"', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '`', '{', '}', '~',
        ] {
            assert!(
                super::kms_endpoint_authority(&format!("https://kms{c}internal.example")).is_err(),
                "{c:?} must be refused"
            );
        }
        // Refused because a URL parser does NOT read them as written: these MOVE the host
        // (verified: url resolves each to a host other than the text before the character).
        assert_eq!(
            super::kms_endpoint_authority("https://kms/internal.example").as_deref(),
            Ok("kms"),
            "'/' ends the authority at the text before it"
        );
        for c in ['#', '?', '@', '\\'] {
            let hostile = format!("https://kms{c}internal.example");
            assert!(
                super::kms_endpoint_authority(&hostile).is_err(),
                "{c:?} must be refused outright"
            );
        }
        // Refused, and url fails outright on them too.
        for c in ['%', '<', '>', '^', '|'] {
            assert!(
                super::kms_endpoint_authority(&format!("https://kms{c}internal.example")).is_err(),
                "{c:?} must be refused"
            );
        }
    }

    /// A bracket-shaped host must be a real IPv6 literal.
    ///
    /// `[foo-bar]`, `[1]` and `[gggg::1]` pass a character allowlist but `url::Url::parse`
    /// refuses all three, so admitting them would only move the failure to the first
    /// request — and it would leave the gate disagreeing with the parser about what the
    /// host even is, which is the property this whole check exists to hold.
    #[test]
    fn a_bracketed_host_must_be_an_ipv6_literal() {
        for hostile in [
            "https://[foo-bar]",
            "https://[1]",
            "https://[gggg::1]",
            "https://[]",
            "https://[::1",
            "https://[::1]junk",
            "http://[fe80::1%25eth0]",
        ] {
            assert!(
                super::kms_endpoint_authority(hostile).is_err(),
                "{hostile} is not an IPv6 endpoint and must be refused"
            );
        }
        // POSITIVE CONTROL: the real IPv6 spellings, including the canonicalisations a URL
        // parser performs. `[0:0:0:0:0:0:0:1]` IS ::1, so the loopback rule must see it.
        for allowed in [
            "https://[2001:db8::1]",
            "https://[2001:db8::1]:8443",
            "https://[::ffff:192.168.0.1]",
            "http://[::1]",
            "http://[::1]:4566",
            "http://[0:0:0:0:0:0:0:1]:4566",
        ] {
            assert!(
                super::kms_endpoint_authority(allowed).is_ok(),
                "{allowed} is a real IPv6 endpoint and must be accepted: {:?}",
                super::kms_endpoint_authority(allowed).err()
            );
        }
    }

    /// A host whose last label is a NUMBER is read by a URL parser as an IPv4 address and
    /// rewritten, so the text is not the host reached — `0x7f.1`, `127.1` and `2130706433`
    /// all become 127.0.0.1, `1.1` becomes 1.0.0.1. Admitted only as a plain dotted quad,
    /// where the two agree.
    #[test]
    fn a_host_that_ends_in_a_number_must_already_be_the_address_it_resolves_to() {
        for rewritten in [
            "https://0x7f.1",
            "https://127.1",
            "https://2130706433",
            "https://1.1",
            "https://0x01010101",
            "https://kms.example.1",
            "http://127.1:4566",
        ] {
            assert!(
                super::kms_endpoint_authority(rewritten).is_err(),
                "{rewritten} is rewritten by a URL parser and must be refused"
            );
        }
        // POSITIVE CONTROL: dotted quads and ordinary names are untouched. A DNS name is
        // never affected — a top-level label cannot be all-numeric.
        for allowed in [
            "https://10.0.0.5:8443",
            "https://192.168.0.1",
            "http://127.0.0.1:4566",
            "https://kms.us-east-1.amazonaws.com",
            "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
            "https://kms-2.example.com",
        ] {
            assert!(
                super::kms_endpoint_authority(allowed).is_ok(),
                "{allowed} must be accepted: {:?}",
                super::kms_endpoint_authority(allowed).err()
            );
        }
    }

    /// A port is a u16, not "some digits".
    ///
    /// `:65536` and `:99999999` are all-digit and `url::Url::parse` refuses both, so an
    /// all-digit rule admitted endpoints no request could ever be made to — a real
    /// disagreement with the parser, in the direction of accepting the unusable. A leading
    /// zero is refused for the narrower reason that `:0443` reaches port 443 while the text
    /// says otherwise.
    #[test]
    fn a_port_must_be_a_tcp_port_number() {
        for bad in [
            "https://kms.example.com:65536",
            "https://kms.example.com:99999999",
            "https://kms.example.com:0443",
            "https://kms.example.com:00",
            // `u16::from_str` accepts a leading sign; `url::Url::parse` refuses both.
            "https://kms.example.com:+443",
            "https://kms.example.com:-443",
            "https://kms.example.com:",
            "http://127.0.0.1:65536",
        ] {
            assert!(
                super::kms_endpoint_authority(bad).is_err(),
                "{bad} is not a usable endpoint and must be refused"
            );
        }
        for good in [
            "https://kms.example.com:65535",
            "https://kms.example.com:443",
            "https://kms.example.com:8443",
            "http://127.0.0.1:4566",
            "http://[::1]:1",
        ] {
            assert!(
                super::kms_endpoint_authority(good).is_ok(),
                "{good} names a real port and must be accepted: {:?}",
                super::kms_endpoint_authority(good).err()
            );
        }
    }

    /// The plaintext exception is decided from the parsed address, so a spelling a URL
    /// parser canonicalises does not change the answer — and every address in 127.0.0.0/8
    /// is loopback, not just `127.0.0.1`.
    #[test]
    fn the_plaintext_exception_follows_the_address_not_the_spelling() {
        for loopback in [
            "http://127.0.0.1:4566",
            "http://127.0.0.2:4566",
            "http://127.255.255.254",
            "http://[0:0:0:0:0:0:0:1]",
        ] {
            assert!(
                super::kms_endpoint_authority(loopback).is_ok(),
                "{loopback} provably names this machine and must be accepted: {:?}",
                super::kms_endpoint_authority(loopback).err()
            );
        }
        for off_machine in [
            "http://128.0.0.1",
            "http://10.0.0.5:8443",
            "http://[fe80::1]",
            "http://[2001:db8::1]",
            "http://localhost.attacker.example",
            // A NAME is refused even when it is conventionally loopback: what `localhost`
            // reaches is the host resolver's answer, which this rule cannot see.
            "http://localhost",
            "http://localhost:4566",
            "http://LOCALHOST:4566",
            // The IPv4 shorthands url reads as 127.0.0.1 are refused, not admitted: a
            // refusal is the safe direction and no operator writes an emulator this way.
            "http://127.1",
            "http://0x7f.1",
        ] {
            assert!(
                super::kms_endpoint_authority(off_machine).is_err(),
                "{off_machine} does not provably name this machine and must be refused"
            );
        }
    }

    /// The refusal of a loopback NAME tells the operator the address form that works.
    #[test]
    fn a_plaintext_name_is_refused_with_the_address_form_named() {
        let err = super::kms_endpoint_authority("http://localhost:4566")
            .expect_err("a plaintext endpoint named by a name must be refused");
        assert!(err.contains("http://127.0.0.1:4566"), "{err}");
    }

    /// The authority the AWS SigV4 `Host` header is built from is the one a URL parser will
    /// connect to, including the port.
    #[test]
    fn the_authority_returned_is_the_host_and_port_that_will_be_reached() {
        for (endpoint, authority) in [
            (
                "https://kms.us-east-1.amazonaws.com",
                "kms.us-east-1.amazonaws.com",
            ),
            (
                "https://kms.us-east-1.amazonaws.com/",
                "kms.us-east-1.amazonaws.com",
            ),
            ("http://127.0.0.1:4566/", "127.0.0.1:4566"),
            ("http://[::1]:4566", "[::1]:4566"),
            ("http://[::1]", "[::1]"),
        ] {
            assert_eq!(
                super::kms_endpoint_authority(endpoint).expect("admissible"),
                authority
            );
        }
    }

    /// The agreement the module exists to hold, MEASURED against the parser the client
    /// links: every endpoint this rule admits is read by `ureq` as the same host and port
    /// the authority names. Gated with the backends, the only builds that link `ureq` and
    /// send a credential.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    #[test]
    fn every_admitted_endpoint_is_read_identically_by_the_client_url_parser() {
        let admitted: Vec<String> = admission_corpus()
            .into_iter()
            .filter(|endpoint| super::kms_endpoint_authority(endpoint).is_ok())
            .collect();
        assert!(
            !admitted.is_empty(),
            "the corpus admitted nothing; the probe measured nothing"
        );
        for endpoint in &admitted {
            assert_client_reads_the_authority_named(endpoint);
        }
        assert_probe_sees_the_client_rewrite_the_text();
        assert_userinfo_demotes_the_recognisable_half();
    }

    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    const ADMISSION_CORPUS: [&str; 35] = [
        "https://kms.us-east-1.amazonaws.com:8443",
        "https://kms.us-east-1.amazonaws.com",
        "https://kms.us-east-1.amazonaws.com/",
        "https://kms.example.com",
        "https://kms.example.com:65535",
        "https://kms.example.com:443",
        "https://kms.example.com:8443",
        "https://kms.example.com:65536",
        "https://kms.example.com:0443",
        "https://kms_internal.example:8443",
        "http://kms_local:4566",
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
        "https://[::ffff:192.168.0.1]",
        "http://[::1]",
        "http://[::1]:4566",
        "http://[0:0:0:0:0:0:0:1]:4566",
        "http://[0:0:0:0:0:0:0:1]",
        "https://10.0.0.5:8443",
        "https://192.168.0.1",
        "http://127.0.0.1:4566",
        "http://127.0.0.2:4566",
        "http://127.255.255.254",
        "http://localhost:4566/",
        "http://LOCALHOST:4566",
        "http://128.0.0.1",
        "http://10.0.0.5:8443",
        "http://[fe80::1]",
        "http://localhost.attacker.example",
        "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
        "https://kms-2.example.com",
        "https://KMS.Example.COM:443",
        "https://kms.example.com.",
        "http://localhost:80@evil.example.com",
        "https://kms/internal.example",
    ];

    /// The punctuation a URL parser reads verbatim, moves the host over, or refuses.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    const HOSTILE_HOST_CHARS: [char; 26] = [
        '!', '"', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '`', '{', '}', '~', '#', '/',
        '?', '@', '\\', '%', '<', '>', '^', '|',
    ];

    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn admission_corpus() -> Vec<String> {
        let mut corpus: Vec<String> = ADMISSION_CORPUS.iter().map(|e| (*e).to_owned()).collect();
        corpus.extend(
            HOSTILE_HOST_CHARS
                .iter()
                .map(|c| format!("https://kms{c}internal.example")),
        );
        corpus
    }

    /// The client reads the same host and port the admitted authority names.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn assert_client_reads_the_authority_named(endpoint: &str) {
        use std::net::Ipv6Addr;
        use std::str::FromStr;

        let authority = super::kms_endpoint_authority(endpoint).expect("admitted");
        let (read_host, read_port) = client_reads(endpoint)
            .unwrap_or_else(|| panic!("{endpoint} is admitted but the client refuses it"));
        let (host, port) = super::split_authority(&authority, &locator())
            .unwrap_or_else(|e| panic!("{endpoint}: {e}"));
        if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let read = read_host.trim_matches(|c| c == '[' || c == ']');
            assert_eq!(
                Ipv6Addr::from_str(inner).ok(),
                Ipv6Addr::from_str(read).ok(),
                "{endpoint}: the client reads a different IPv6 host"
            );
        } else {
            assert_eq!(
                read_host.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                "{endpoint}: the client reads a different host"
            );
        }
        let written = match port {
            Some(p) => p.parse::<u16>().ok(),
            None if endpoint.starts_with("https://") => Some(443),
            None => Some(80),
        };
        assert_eq!(
            Some(read_port),
            written,
            "{endpoint}: the client reads a different port"
        );
    }

    /// POSITIVE CONTROL: the probe sees a disagreement when one exists. The client reads
    /// each of these as a host or port other than the literal text, and the rule refuses
    /// each.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn assert_probe_sees_the_client_rewrite_the_text() {
        for (endpoint, text_host, text_port) in [
            ("https://127.1", "127.1", None),
            ("https://0x7f.1", "0x7f.1", None),
            ("https://2130706433", "2130706433", None),
            ("https://1.1", "1.1", None),
            (
                "https://kms.example.com:0443",
                "kms.example.com",
                Some("0443"),
            ),
            (
                "https://cloudkms.googleapis.com@evil.example.com",
                "cloudkms.googleapis.com",
                None,
            ),
        ] {
            let (read_host, read_port) = client_reads(endpoint)
                .unwrap_or_else(|| panic!("{endpoint} must still parse in the client"));
            let port_differs = text_port.is_some_and(|p| read_port.to_string() != p);
            assert!(
                read_host != text_host
                    || port_differs
                    || connects_elsewhere(&read_host, read_port, text_host),
                "{endpoint}: the probe failed to see the client rewrite the text"
            );
            assert!(
                super::kms_endpoint_authority(endpoint).is_err(),
                "{endpoint} is read differently by the client and must be refused"
            );
        }
    }

    /// Userinfo demotes the recognisable half: the client connects to the host after the
    /// `@`, which is why the rule refuses every authority carrying one.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn assert_userinfo_demotes_the_recognisable_half() {
        for endpoint in [
            "https://cloudkms.googleapis.com@evil.example.com",
            "https://kms.us-east-1.amazonaws.com@evil.example.com/",
            "https://sts.eu-north-1.amazonaws.com@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://127.0.0.1:8080@evil.example.com",
            "http://localhost@evil.example.com",
            "https://user:pass@evil.example.com",
            "https://@evil.example.com",
        ] {
            assert_eq!(
                client_reads(endpoint).map(|(host, _)| host).as_deref(),
                Some("evil.example.com"),
                "{endpoint}: the client reads another host"
            );
            assert!(
                super::kms_endpoint_authority(endpoint).is_err(),
                "{endpoint}"
            );
        }
    }

    /// The `host` and port the client connects to for `endpoint`: ureq parses a request URL
    /// as an `http::Uri`, resolves its authority's host, and takes the explicit port or the
    /// scheme's default. `None` when the client refuses the URL.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn client_reads(endpoint: &str) -> Option<(String, u16)> {
        let uri: ureq::http::Uri = endpoint.parse().ok()?;
        let authority = uri.authority()?;
        let default = match uri.scheme_str()? {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        Some((
            authority.host().to_owned(),
            authority.port_u16().unwrap_or(default),
        ))
    }

    /// Whether the address the client's resolver yields for a numeric `host` is spelled
    /// differently from `text`: `127.1` and `2130706433` are names to the URL parser and
    /// `127.0.0.1` to the resolver it hands them to. Resolved without DNS, because every
    /// host asked about here is numeric.
    #[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
    fn connects_elsewhere(host: &str, port: u16, text: &str) -> bool {
        use std::net::ToSocketAddrs;
        (host, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .is_some_and(|addr| addr.ip().to_string() != text)
    }

    /// One credential-bearing endpoint, what must not reach its refusal, and what the
    /// operator must still learn from it.
    struct Refusal<'a> {
        configured: &'a str,
        leaked: &'a [&'a str],
        reported: (&'a str, &'a str),
        why: &'a str,
    }

    fn assert_refusal_hides_the_configured_value(case: Refusal<'_>) {
        let message = super::kms_endpoint_authority(case.configured).expect_err(case.why);
        for secret in case.leaked {
            assert!(
                !message.contains(secret),
                "the configured credential reached the refusal: {message}"
            );
        }
        assert!(
            !message.contains(case.configured),
            "the complete configured endpoint was echoed: {message}"
        );
        let (named, component) = case.reported;
        assert!(
            message.contains(named) && message.contains(component),
            "an operator must still learn where the request goes and which component: {message}"
        );
    }

    /// A stand-in for the projected whole the predicates below carry into their refusals.
    /// Each predicate is being asked about its OWN argument here; the rendered whole is a
    /// constant for every case, so one is shared rather than restated per call.
    fn locator() -> super::RedactedLocator {
        super::RedactedLocator::of("https://kms.example.com")
    }

    // --- the subordinate predicates, exercised directly -------------------------------
    //
    // The cases above reach these through `kms_endpoint_authority`, which is the contract
    // callers depend on. These reach each predicate on its own, so a refusal that stops
    // firing is attributed to the check that owns it rather than surfacing as one opaque
    // failure of the whole rule. Each carries its negative control: the admitted case
    // sitting beside the refused one, so a predicate that started refusing everything
    // would fail here rather than look like a stricter policy.

    #[test]
    fn split_authority_divides_on_the_bracket_not_the_first_colon() {
        // The whole reason this is a separate step: `[::1]:4566` contains four colons and
        // only the last one is the port separator.
        assert_eq!(
            super::split_authority("[::1]:4566", &locator()).expect("admissible"),
            ("[::1]", Some("4566"))
        );
        assert_eq!(
            super::split_authority("[::1]", &locator()).expect("admissible"),
            ("[::1]", None)
        );
        assert_eq!(
            super::split_authority("host:443", &locator()).expect("admissible"),
            ("host", Some("443"))
        );
        assert_eq!(
            super::split_authority("host", &locator()).expect("admissible"),
            ("host", None)
        );
    }

    #[test]
    fn split_authority_refuses_a_bracket_that_does_not_close_or_is_followed_by_junk() {
        assert!(super::split_authority("[::1", &locator()).is_err());
        assert!(super::split_authority("[::1]x443", &locator()).is_err());
    }
}
