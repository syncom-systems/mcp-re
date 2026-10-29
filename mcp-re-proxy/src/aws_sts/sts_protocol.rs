// SPDX-License-Identifier: Apache-2.0
//! The STS wire codec: the bytes of an `AssumeRoleWithWebIdentity` exchange, in both
//! directions, over a peer this module does not trust.
//!
//! It owns reading a bounded body, encoding the request form, and turning a response into
//! a credential and its expiry. It decides nothing about caching or about when to exchange;
//! that is [`super::WebIdentityCredentialSource`]'s. It reads no clock: the instant a
//! response is judged at is the caller's.

use std::io::Read;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use zeroize::Zeroizing;

use super::CachedCredentials;
use crate::aws_sigv4::AwsCredentials;
use crate::key_source::KeyError;

/// The longest session an `AssumeRoleWithWebIdentity` credential is believed on.
///
/// A role's `MaxSessionDuration` cannot exceed 12 hours, so an `Expiration` beyond that is
/// not a lifetime STS can honestly have issued. Unbounded, a substituted or emulator
/// endpoint stating a far-future `Expiration` pins the credential for the process lifetime
/// — nothing re-exchanges it unless KMS refuses it as expired, which a substitute can avoid — a loss of
/// AWS-rooted signing on that replica.
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

/// Read a credential-bearing input whole, or refuse it.
///
/// Past `cap` the input is REFUSED, not truncated, so no reader of the result has to know
/// that a cut document happens to fail to parse. The buffer scrubs on drop and is allocated
/// at `cap + 1` before the first byte, so no reallocation leaves an unscrubbed copy of the
/// credential behind. `what` names the input in either refusal.
pub(super) fn read_capped(
    source: impl Read,
    cap: u64,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let limit = cap.saturating_add(1);
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(limit).unwrap_or(0)));
    source
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| KeyError::NotFound(format!("aws-kms: read {what}: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(KeyError::Malformed(format!(
            "aws-kms: {what} exceeds the {cap}-byte cap"
        )));
    }
    Ok(buf)
}

/// Percent-encode for `application/x-www-form-urlencoded`.
///
/// Unreserved characters pass through; everything else — including the `+`, `/` and
/// `=` a JWT's base64url padding and an ARN's separators produce — is escaped. A
/// bare `+` in a form body decodes as a space, which would corrupt the very token
/// being presented, so this is not cosmetic.
pub(super) fn form_encode(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(3)));
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pull the `<Credentials>` element out of an `AssumeRoleWithWebIdentityResponse`.
///
/// A narrow extractor rather than an XML dependency: STS's query protocol is XML
/// only, and the four values wanted are flat leaf elements inside one container. The
/// extraction is scoped to the text *between* `<Credentials>` and `</Credentials>`
/// so a value echoed elsewhere in the document (`<Audience>`, `<SubjectFrom...>`,
/// an error string) cannot be mistaken for the credential.
///
/// `now` is the instant the response is judged at, and it bounds the lifetime ceiling. The
/// caller reads the clock, so this codec holds no clock authority.
pub(super) fn parse_assume_role_response(
    xml: &str,
    now: SystemTime,
) -> Result<CachedCredentials, KeyError> {
    let creds = element_text(xml, "Credentials").ok_or_else(|| {
        KeyError::Malformed(
            "aws-kms: STS response has no <Credentials> element (not an \
             AssumeRoleWithWebIdentity response?)"
                .to_string(),
        )
    })?;
    let field = |name: &str| -> Result<String, KeyError> {
        element_text(creds, name)
            .map(decode_xml_entities)
            .ok_or_else(|| {
                KeyError::Malformed(format!("aws-kms: STS credentials have no <{name}>"))
            })
    };
    let access_key_id = field("AccessKeyId")?;
    let secret_access_key = Zeroizing::new(field("SecretAccessKey")?);
    let session_token = Zeroizing::new(field("SessionToken")?);
    if access_key_id.is_empty() || secret_access_key.is_empty() || session_token.is_empty() {
        return Err(KeyError::Malformed(
            "aws-kms: STS returned an empty credential field".to_string(),
        ));
    }
    // An absent or unparseable Expiration parses to UNIX_EPOCH — already expired, never
    // unlimited. This function establishes only that no expiry could be read; how long
    // such a credential may then be reused is `cached_or_exchange`'s decision, and it is
    // bounded by UNKNOWN_EXPIRY_REUSE rather than open-ended. What must not exist is a
    // path where an unreadable Expiration becomes a credential held indefinitely.
    //
    // The TOP is bounded too, and for the same reason the GCP sibling clamps `expires_in`:
    // an `Expiration` of year 9999 parses cleanly and pins the credential for the process
    // lifetime, so CREDENTIAL_REFRESH_MARGIN never fires again and nothing re-exchanges —
    // a credential KMS refuses as expired is evicted and re-exchanged once, but one it accepts is not, so that state is
    // permanent until a restart. `AssumeRoleWithWebIdentity` cannot issue a session longer
    // than the role's MaxSessionDuration, whose own ceiling is 12 hours, so a longer claim
    // is not a lifetime the peer can honestly promise. Truncating is a truthful bound, not
    // a guess.
    let expires_at = field("Expiration")
        .ok()
        .and_then(|s| mcp_re_core::parse_rfc3339_utc(&s).ok())
        .and_then(|unix| u64::try_from(unix).ok())
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .map(|stated| stated.min(now + MAX_SESSION_LIFETIME))
        .unwrap_or(UNIX_EPOCH);
    Ok(CachedCredentials {
        credentials: AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token: Some(session_token),
        },
        expires_at,
    })
}

/// The text between the first `<name>` and the following `</name>`, or `None`.
///
/// Deliberately does not handle attributes, namespaces or self-closing tags: STS's
/// credential elements have none, and an input that does have them is not a response
/// this function should be guessing about.
fn element_text<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

/// Decode the five predefined XML entities.
///
/// Base64 and ARN characters never need escaping, so in practice this is the
/// identity function — but "in practice" is how a decoder that silently hands back
/// `&amp;` inside a secret gets written, and a corrupted secret key fails as an
/// opaque KMS `InvalidSignatureException` far from here.
fn decode_xml_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` LAST: doing it first would let `&amp;lt;` decode to `<`.
        .replace("&amp;", "&")
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::aws_sts) fn response_with(expiration: &str) -> String {
        format!(
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::455880745808:assumed-role/mcp-re-kms-signer/mcp-re-proxy</Arn>
      <AssumedRoleId>AROAEXAMPLE:mcp-re-proxy</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLEKEYID</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>FQoGZXIvYXdzEExampleToken==</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
    <Provider>arn:aws:iam::455880745808:oidc-provider/oidc.eks.eu-north-1.amazonaws.com/id/EXAMPLE</Provider>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#
        )
    }

    #[test]
    fn a_well_formed_response_yields_the_credentials_and_its_expiry() {
        let parsed =
            parse_assume_role_response(&response_with("2026-08-03T12:34:56Z"), SystemTime::now())
                .unwrap();
        assert_eq!(parsed.credentials.access_key_id, "ASIAEXAMPLEKEYID");
        assert_eq!(
            &*parsed.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            parsed.credentials.session_token.as_deref().map(|s| &**s),
            Some("FQoGZXIvYXdzEExampleToken==")
        );
        let expected = UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(mcp_re_core::parse_rfc3339_utc("2026-08-03T12:34:56Z").unwrap())
                    .unwrap(),
            );
        assert_eq!(parsed.expires_at, expected);
    }

    #[test]
    fn a_session_token_is_always_set_so_sigv4_sends_x_amz_security_token() {
        // Web-identity credentials are ALWAYS temporary. If this ever parsed to
        // `None` the SigV4 signer would omit `X-Amz-Security-Token` and every KMS
        // call would fail authentication for a reason that points nowhere near here.
        let parsed =
            parse_assume_role_response(&response_with("2026-08-03T12:34:56Z"), SystemTime::now())
                .unwrap();
        assert!(parsed.credentials.session_token.is_some());
    }

    #[test]
    fn an_unparseable_expiration_reads_as_already_expired_not_as_unlimited() {
        let parsed =
            parse_assume_role_response(&response_with("not-a-timestamp"), SystemTime::now())
                .unwrap();
        assert_eq!(parsed.expires_at, UNIX_EPOCH);
        // No freshness gate can ever be satisfied by it, which is why
        // `cached_or_exchange` replaces an at-or-before-now expiry with the bounded
        // `UNKNOWN_EXPIRY_REUSE` floor instead of caching the raw value.
        assert!(SystemTime::now() + crate::aws_sts::CREDENTIAL_REFRESH_MARGIN >= parsed.expires_at);
    }

    #[test]
    fn a_missing_expiration_element_reads_as_already_expired() {
        let xml = r#"<Credentials>
          <AccessKeyId>A</AccessKeyId>
          <SecretAccessKey>B</SecretAccessKey>
          <SessionToken>C</SessionToken>
        </Credentials>"#;
        assert_eq!(
            parse_assume_role_response(xml, SystemTime::now())
                .unwrap()
                .expires_at,
            UNIX_EPOCH
        );
    }

    #[test]
    fn a_response_without_credentials_is_refused() {
        let xml = r#"<ErrorResponse><Error><Code>AccessDenied</Code>
          <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message>
        </Error></ErrorResponse>"#;
        let err = parse_assume_role_response(xml, SystemTime::now()).unwrap_err();
        assert!(format!("{err:?}").contains("Credentials"), "got: {err:?}");
    }

    #[test]
    fn each_missing_credential_field_is_named() {
        for missing in ["AccessKeyId", "SecretAccessKey", "SessionToken"] {
            let full = response_with("2026-08-03T12:34:56Z");
            let stripped = full
                .lines()
                .filter(|l| !l.contains(&format!("<{missing}>")))
                .collect::<Vec<_>>()
                .join("\n");
            let err = parse_assume_role_response(&stripped, SystemTime::now()).unwrap_err();
            assert!(format!("{err:?}").contains(missing), "got: {err:?}");
        }
    }

    #[test]
    fn an_empty_credential_field_is_refused_rather_than_signed_with() {
        let xml = r#"<Credentials>
          <AccessKeyId></AccessKeyId>
          <SecretAccessKey>B</SecretAccessKey>
          <SessionToken>C</SessionToken>
          <Expiration>2026-08-03T12:34:56Z</Expiration>
        </Credentials>"#;
        assert!(parse_assume_role_response(xml, SystemTime::now()).is_err());
    }

    #[test]
    fn a_value_echoed_outside_credentials_is_not_mistaken_for_one() {
        // `<Audience>` precedes `<Credentials>` in a real response. If the extractor
        // searched the whole document per field rather than the Credentials subtree,
        // a document that echoed `<AccessKeyId>` earlier would win.
        let xml = r#"<Response>
          <Decoy><AccessKeyId>ATTACKERKEY</AccessKeyId></Decoy>
          <Credentials>
            <AccessKeyId>REALKEY</AccessKeyId>
            <SecretAccessKey>B</SecretAccessKey>
            <SessionToken>C</SessionToken>
            <Expiration>2026-08-03T12:34:56Z</Expiration>
          </Credentials>
        </Response>"#;
        let parsed = parse_assume_role_response(xml, SystemTime::now()).unwrap();
        assert_eq!(parsed.credentials.access_key_id, "REALKEY");
    }

    #[test]
    fn form_encoding_escapes_what_a_jwt_and_an_arn_contain() {
        // A bare `+` decodes as a space on the server, corrupting the token.
        assert_eq!(form_encode("a+b/c=d").as_str(), "a%2Bb%2Fc%3Dd");
        assert_eq!(
            form_encode("arn:aws:iam::455880745808:role/mcp-re").as_str(),
            "arn%3Aaws%3Aiam%3A%3A455880745808%3Arole%2Fmcp-re"
        );
        // Unreserved characters are left alone.
        assert_eq!(form_encode("Az0-_.~").as_str(), "Az0-_.~");
    }

    #[test]
    fn a_credential_read_past_its_cap_is_refused_not_truncated() {
        let whole = read_capped(&b"abcd"[..], 4, "x").expect("at the cap is admitted");
        assert_eq!(whole.as_slice(), b"abcd");
        let empty = read_capped(&b""[..], 4, "x").expect("empty is admitted");
        assert!(empty.is_empty());
        assert!(matches!(
            read_capped(&b"abcde"[..], 4, "x"),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn xml_entities_decode_and_amp_is_decoded_last() {
        assert_eq!(decode_xml_entities("a&amp;b"), "a&b");
        assert_eq!(decode_xml_entities("a&lt;b&gt;c"), "a<b>c");
        // `&amp;lt;` is the ESCAPED form of the literal text `&lt;` — decoding
        // `&amp;` first would turn it into `<`, inventing a character.
        assert_eq!(decode_xml_entities("&amp;lt;"), "&lt;");
        // The no-entity fast path must not alter anything.
        assert_eq!(
            decode_xml_entities("plain/base64+value=="),
            "plain/base64+value=="
        );
    }

    /// A stated `Expiration` is bounded above, so no response can pin a credential for the
    /// process lifetime.
    ///
    /// Nothing here evicts a cached credential when KMS rejects it, so an unbounded
    /// `Expiration` is not merely a long cache — it is a permanent one: the refresh margin
    /// never fires, no exchange ever runs again, and AWS-rooted signing is lost on that
    /// replica until it restarts. `AssumeRoleWithWebIdentity` cannot issue past a role's
    /// MaxSessionDuration, whose ceiling is 12 hours, so a longer claim is not a lifetime
    /// STS can honestly have issued.
    #[test]
    fn a_far_future_expiration_is_truncated_to_the_real_session_ceiling() {
        let now = SystemTime::now();
        let pinned = parse_assume_role_response(&response_with("9999-01-01T00:00:00Z"), now)
            .expect("parses");
        assert_eq!(
            pinned.expires_at,
            now + MAX_SESSION_LIFETIME,
            "a year-9999 Expiration must be truncated, not trusted"
        );
        // POSITIVE CONTROL: an ordinary one-hour session is passed through untouched, and
        // an unreadable one still lands on the already-expired sentinel that the reuse
        // floor keys on.
        let real = mcp_re_core::parse_rfc3339_utc("2026-08-03T12:34:56Z").expect("fixture");
        let ordinary = parse_assume_role_response(&response_with("2026-08-03T12:34:56Z"), now)
            .expect("parses");
        assert_eq!(
            ordinary.expires_at,
            UNIX_EPOCH + Duration::from_secs(real as u64),
            "a real Expiration must be used exactly as stated"
        );
        assert_eq!(
            parse_assume_role_response(&response_with("not-a-timestamp"), now)
                .expect("parses")
                .expires_at,
            UNIX_EPOCH,
            "an unreadable Expiration must stay the already-expired sentinel"
        );
    }
}
