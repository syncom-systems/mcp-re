//! The one network fetch of the OCSP check: POST the DER request to a vetted destination and
//! return the response body, bounded.
//!
//! This is the module's only I/O. Nothing here interprets the response: trust is decided by
//! the pure pipeline over the bytes this returns.

use std::io::Read;
use std::time::Duration;

use crate::outbound_fetch::FetchWith;
use crate::outbound_fetch::RequestBound;
use crate::outbound_fetch::VettedDestination;

use super::OcspError;

/// Cap on the OCSP response body read (64 KiB). A legitimate single-cert OCSP
/// response is well under a kilobyte; this defends against a hostile or
/// misbehaving responder streaming an unbounded body into the serving thread.
const MAX_OCSP_RESPONSE_BYTES: u64 = 64 * 1024;

/// POST a DER OCSP request to `destination` and return the raw response body bytes.
/// Any HTTP/timeout/transport error is `Err`.
///
/// The SSRF posture is not decided here and cannot be: the agent comes from the
/// destination, which knows its own provenance. Redirects are disabled for every
/// provenance and the resolved-address vetting is installed for a certificate-derived
/// one — see [`crate::outbound_fetch::VettedDestination::agent`] for both arguments.
/// What this function still owns is the RESPONSE bound: a well-formed OCSP response is
/// well under a kilobyte, and a hostile responder streaming an unbounded body into the
/// serving thread is refused by the read cap rather than by the network.
///
/// A transport failure is reported by its kind, never by `ureq`'s rendering of it: that
/// rendering prefixes the request URL, and an operator-configured URL may carry userinfo.
pub(super) fn post(
    destination: &VettedDestination,
    timeout: Duration,
    request_der: &[u8],
) -> Result<Vec<u8>, OcspError> {
    let response = destination
        .agent(timeout)
        .post(destination.url())
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .bounded_by(timeout)
        .fetch_with(request_der)
        .map_err(|e| OcspError::Http(e.kind().to_owned()))?;
    // Bound the response body read so a hostile/oversized responder reply
    // cannot exhaust memory; a well-formed OCSP response is small.
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_OCSP_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| OcspError::ReadBody(e.to_string()))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::post;
    use crate::ocsp::DEFAULT_OCSP_TIMEOUT;
    use crate::outbound_fetch::VettedDestination;

    use std::time::Duration;

    /// A transport error never renders the credential in the operator-configured URL, nor
    /// the URL itself.
    #[test]
    fn a_credential_in_the_responder_url_reaches_no_operational_text() {
        const URL: &str = "http://user:s3cret@127.0.0.1:1/ocsp";
        let destination = VettedDestination::operator_configured(URL).expect("loopback http");
        let error = post(&destination, DEFAULT_OCSP_TIMEOUT, b"x")
            .expect_err("nothing listens on 127.0.0.1:1");
        let rendered = error.to_string();
        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1:1/ocsp"), "{rendered}");
    }

    /// A TCP listener on loopback and its address.
    fn loopback_listener() -> (std::net::TcpListener, std::net::SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("listener addr");
        (listener, addr)
    }

    /// A responder that accepts one connection, reads the POST, and replies `302` to
    /// `redirect_to`. The returned flag is set once the responder was reached, so a clean
    /// sentinel cannot be a false pass from a failed first request.
    fn spawn_redirecting_responder(
        responder: std::net::TcpListener,
        redirect_to: String,
    ) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        use std::io::Read;
        use std::io::Write;
        use std::sync::atomic::Ordering;
        let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hit_flag = std::sync::Arc::clone(&hit);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = responder.accept() {
                hit_flag.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        hit
    }

    /// Wait (bounded) for the responder thread to observe the connection.
    fn responder_was_reached(hit: &std::sync::atomic::AtomicBool) -> bool {
        use std::sync::atomic::Ordering;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !hit.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        hit.load(Ordering::SeqCst)
    }

    /// Stage-2 audit regression: the responder-host SSRF guard only inspects the
    /// FIRST URL, so a guarded responder that replies `302 Location:
    /// http://<internal>/` must NOT be chased — `ureq` follows redirects by default,
    /// which would reach an address that never passed the guard. This drives the real
    /// fetch (`post`) against a local responder that 302s to a SENTINEL
    /// listener standing in for the internal target, and asserts the sentinel is
    /// never contacted.
    #[test]
    fn ocsp_post_does_not_follow_redirects() {
        // The "internal" target the redirect points at. Non-blocking so we can probe
        // for a connection without hanging the test.
        let (sentinel, sentinel_addr) = loopback_listener();
        sentinel
            .set_nonblocking(true)
            .expect("sentinel nonblocking");
        let (responder, responder_addr) = loopback_listener();
        let hit = spawn_redirecting_responder(responder, format!("http://{sentinel_addr}/"));

        // The result itself is irrelevant (a 302 carries no valid OCSP body); the
        // security property is that NO request reaches the sentinel.
        // OPERATOR-CONFIGURED, and that is the honest description: this responder is on
        // 127.0.0.1, which is exactly the address a certificate may not name and an
        // operator may. Saying so is also what removed the checker's test-only vetting
        // kill switch — with the provenance on the DESTINATION, a test that needs a
        // loopback responder states it at the destination instead of disabling a guard.
        //
        // Redirects are disabled for EVERY provenance, so this still exercises the
        // property under test.
        let destination =
            VettedDestination::operator_configured(format!("http://{responder_addr}/ocsp"))
                .expect("an http loopback URL is a legal operator-configured destination");
        let _ = post(&destination, DEFAULT_OCSP_TIMEOUT, b"dummy-ocsp-request");

        assert!(
            responder_was_reached(&hit),
            "the OCSP fetch never reached the responder — test would false-pass; check the harness"
        );
        match sentinel.accept() {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Correct: redirects disabled, the internal target was never reached.
            }
            Ok(_) => panic!(
                "OCSP fetch FOLLOWED the 302 redirect to the internal sentinel — SSRF redirect bypass"
            ),
            Err(e) => panic!("unexpected sentinel accept error: {e}"),
        }
    }
}
