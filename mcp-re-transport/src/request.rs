// SPDX-License-Identifier: Apache-2.0
//! Building the request bytes, and refusing anything that could be read two ways.
//!
//! This transport owns the framing, so it owns the headers that define where one message
//! ends and the next begins. A caller that could set `Host`, `Content-Length`, `Connection`
//! or `Transfer-Encoding` could desynchronise the message boundary from what the peer
//! parses — the classic request-smuggling shape — so supplying one FAILS CLOSED rather than
//! being silently dropped or duplicated. Silently dropping it would be worse than refusing:
//! the caller believes it sent something the peer never saw.
//!
//! Everything else the caller supplies is held to RFC 9110 before a socket is opened. A
//! method that is not a token, an origin-form target carrying a space (which would end the
//! target and let the rest be read as the HTTP version), a header name that is not a token,
//! a value carrying a control character — each one is a second framing interpretation
//! available to the peer, and each is a local programming error rather than something to
//! discover with a connection already established.

use super::TransportError;

/// Headers this transport owns because it owns the framing. A caller that could
/// set them could desynchronise the message boundary from what the peer parses —
/// the classic request-smuggling shape — so supplying one fails closed rather
/// than being silently dropped or duplicated.
const TRANSPORT_OWNED_HEADERS: [&str; 4] =
    ["host", "content-length", "connection", "transfer-encoding"];

/// RFC 9110 `tchar`: the characters a method or header name may contain.
pub(super) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The request line, `Host` and body length the transport writes itself. The caller's own
/// headers travel separately because only those are subject to the transport-owned list.
pub(super) struct RequestHead<'a> {
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) host: &'a str,
    pub(super) body_len: usize,
}

fn refuse(reason: String) -> Result<(), TransportError> {
    Err(TransportError::InvalidRequest(reason))
}

fn is_visible_ascii(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

/// A header value byte that could end the header block or hide a second request.
fn is_forbidden_value_byte(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7F
}

fn check_method(method: &str) -> Result<(), TransportError> {
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return refuse(format!("method is not an RFC 9110 token: {method:?}"));
    }
    Ok(())
}

/// Origin-form request target: visible ASCII, no space (which would end the target and let
/// the rest be read as the HTTP version), no CR/LF.
fn check_target(path: &str) -> Result<(), TransportError> {
    if !path.starts_with('/') || !path.bytes().all(is_visible_ascii) {
        return refuse(format!(
            "request target is not origin-form visible ASCII: {path:?}"
        ));
    }
    Ok(())
}

/// The transport emits Host itself; a CR/LF or control byte here is request splitting and is
/// refused like any caller-supplied value.
fn check_host(host: &str) -> Result<(), TransportError> {
    if host.is_empty() || !host.bytes().all(is_visible_ascii) {
        return refuse(format!("Host is not non-empty visible ASCII: {host:?}"));
    }
    Ok(())
}

fn check_header(name: &str, value: &str) -> Result<(), TransportError> {
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return refuse(format!("header name is not an RFC 9110 token: {name:?}"));
    }
    let lower = name.to_ascii_lowercase();
    if TRANSPORT_OWNED_HEADERS.contains(&lower.as_str()) {
        return refuse(format!(
            "{lower} is set by the transport and must not be supplied by the caller"
        ));
    }
    // A CR or LF here would terminate the header block early and let the rest of the value
    // be read as a second request (request splitting). Reject the whole exchange; never
    // sanitise and send.
    if value.bytes().any(is_forbidden_value_byte) {
        return refuse(format!(
            "header {name} carries a control character (request splitting)"
        ));
    }
    Ok(())
}

/// Serialize the request line + header block, validating every value written
/// into the head, including the transport-supplied `Host`. `Host`,
/// `Content-Length` and `Connection` are set here (single request per
/// connection, matching the proxy's framing).
pub(super) fn build_request_head(
    head: &RequestHead<'_>,
    headers: &[(String, String)],
) -> Result<String, TransportError> {
    check_method(head.method)?;
    check_target(head.path)?;
    check_host(head.host)?;
    let RequestHead {
        method,
        path,
        host,
        body_len,
    } = head;
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {body_len}\r\nConnection: close\r\n");
    for (name, value) in headers {
        check_header(name, value)?;
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    /// A head that passes every check; each test overrides the one field it exercises.
    fn valid() -> RequestHead<'static> {
        RequestHead {
            method: "POST",
            path: "/",
            host: "proxy.internal",
            body_len: 0,
        }
    }

    fn assert_refused(head: &RequestHead<'_>, headers: &[(String, String)]) {
        let result = build_request_head(head, headers);
        assert!(
            matches!(result, Err(TransportError::InvalidRequest(_))),
            "must be refused: {result:?}"
        );
    }

    #[test]
    fn caller_headers_are_emitted_verbatim() {
        let head = build_request_head(
            &RequestHead {
                path: "/mcp?route=a",
                body_len: 17,
                ..valid()
            },
            &[
                header("signature", "sig1=:AAAA:"),
                header("content-digest", "sha-256=:BBBB:"),
            ],
        )
        .expect("emittable request");
        assert!(head.starts_with("POST /mcp?route=a HTTP/1.1\r\n"));
        assert!(head.contains("\r\nHost: proxy.internal\r\n"));
        assert!(head.contains("\r\nContent-Length: 17\r\n"));
        assert!(head.contains("\r\nsignature: sig1=:AAAA:\r\n"));
        assert!(head.contains("\r\ncontent-digest: sha-256=:BBBB:\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_crlf_in_a_header_value_is_rejected_not_sanitised() {
        let split = [header("signature", "sig1=:AAAA:\r\nX-Injected: yes")];
        assert_refused(&valid(), &split);
    }

    #[test]
    fn a_bare_lf_in_a_header_value_is_rejected() {
        let split = [header("signature", "sig1=:AAAA:\nX-Injected: yes")];
        assert_refused(&valid(), &split);
    }

    #[test]
    fn a_host_that_is_not_visible_ascii_is_rejected() {
        for host in [
            "proxy.internal\r\nX-Injected: yes",
            "proxy.internal\nX",
            "proxy internal",
            "",
        ] {
            assert_refused(&RequestHead { host, ..valid() }, &[]);
        }
        for host in ["proxy.internal:8443", "::1"] {
            assert!(build_request_head(&RequestHead { host, ..valid() }, &[]).is_ok());
        }
    }

    #[test]
    fn transport_owned_headers_are_refused() {
        for name in ["Host", "content-length", "Connection", "Transfer-Encoding"] {
            assert_refused(&valid(), &[header(name, "x")]);
        }
    }

    #[test]
    fn a_non_token_method_or_header_name_is_rejected() {
        assert_refused(
            &RequestHead {
                method: "PO ST",
                ..valid()
            },
            &[],
        );
        assert_refused(&valid(), &[header("bad name", "x")]);
    }

    #[test]
    fn a_request_target_with_a_space_is_rejected() {
        for path in ["/mcp HTTP/1.1", "mcp"] {
            assert_refused(&RequestHead { path, ..valid() }, &[]);
        }
    }
}
