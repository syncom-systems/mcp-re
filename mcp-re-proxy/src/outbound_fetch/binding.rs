// SPDX-License-Identifier: Apache-2.0
//! Installing this authority's policy into an HTTP client.
//!
//! One fact: **the client a destination hands out enforces the guard that destination
//! passed.** The policy above it — the scheme allowlist, the private-address
//! classification, the `inet_aton` canonicalizer — is unconditional and decides
//! admissibility once. This is the other half, and it is a different thing: a decision
//! already taken becomes a capability that carries it, so that no caller holds a verdict
//! it could act on incorrectly.
//!
//! It lives behind the features that link an HTTP client, for the reason given where they
//! are named. Nothing here decides whether a destination is legitimate.

use std::time::Duration;

use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{Connector, DefaultConnector};

use super::public_roots::RootedConnector;
use super::resolver::VettingResolver;
use super::{Provenance, VettedDestination};

impl VettedDestination {
    /// An HTTP agent configured for THIS destination's provenance.
    ///
    /// Feature-gated with the resolver it installs, for the reason stated above the
    /// module: the guard is unconditional, binding it to an HTTP client cannot be.
    ///
    /// A capability, not a flag. Redirects are disabled for every provenance — a revocation
    /// fetch has no legitimate need to chase a `302 Location: http://169.254.169.254/`, and
    /// the first URL is the only one any guard saw. The resolved-address vetting is
    /// installed only for a certificate-derived destination, for the same reason the
    /// literal-address block is.
    ///
    /// The agent carries `timeout` as its overall request bound, so a request built from it
    /// is bounded even when the call site sets no timeout of its own (a per-request
    /// `timeout_global` overrides it). No proxy is consulted, whatever the environment says:
    /// the connection goes to the vetted destination itself. A non-2xx status is a response,
    /// not an error, so its caller reads the body under its own bound. The time bound covers
    /// connect and I/O, not name resolution. Its TLS authenticates a server against the
    /// public Web PKI roots, through the connector `public_roots` owns, chained after ureq's
    /// own TCP connector.
    pub fn agent(&self, timeout: Duration) -> ureq::Agent {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .proxy(None)
            .timeout_global(Some(timeout))
            .build();
        let connector = DefaultConnector::new().chain(RootedConnector::public());
        match self.provenance {
            Provenance::CertificateDerived => {
                ureq::Agent::with_parts(config, connector, VettingResolver::std())
            }
            Provenance::OperatorConfigured => {
                ureq::Agent::with_parts(config, connector, DefaultResolver::default())
            }
        }
    }
}

/// A per-request time bound on a request built from an agent [`VettedDestination::agent`]
/// handed out. It replaces the agent's own bound for that request.
#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
pub(crate) trait RequestBound {
    fn bounded_by(self, timeout: Duration) -> Self;
}

#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
impl<B> RequestBound for ureq::RequestBuilder<B> {
    fn bounded_by(self, timeout: Duration) -> Self {
        ureq::RequestBuilder::config(self)
            .timeout_global(Some(timeout))
            .build()
    }
}

/// Why a fetched request yielded no body to read: the remote answered with a failure
/// status, whose response is kept so its body can be read under the caller's bound, or no
/// answer arrived.
#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
#[derive(Debug)]
pub(crate) enum Failure {
    Status(u16, Box<ureq::http::Response<ureq::Body>>),
    Transport(ureq::Error),
}

#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
impl Failure {
    /// The class of the failure, without ureq's rendering of it: that rendering can carry
    /// the request URL, and an operator-configured URL may carry userinfo.
    #[cfg(feature = "online_ocsp")]
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Failure::Status(..) => "http status",
            Failure::Transport(ureq::Error::Timeout(_)) => "timeout",
            Failure::Transport(ureq::Error::HostNotFound) => "host not found",
            Failure::Transport(ureq::Error::ConnectionFailed) => "connection failed",
            Failure::Transport(ureq::Error::Io(_)) => "i/o failure",
            Failure::Transport(ureq::Error::Tls(_) | ureq::Error::TlsRequired) => "tls failure",
            Failure::Transport(ureq::Error::BadUri(_)) => "bad url",
            Failure::Transport(_) => "transport failure",
        }
    }
}

#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Status(code, _) => write!(f, "status code {code}"),
            Failure::Transport(error) => error.fmt(f),
        }
    }
}

/// [`FetchWith`] for a request that carries no body.
#[cfg(feature = "gcp_kms_keysource")]
pub(crate) trait Fetch {
    /// The request as built, with no body.
    fn fetch(self) -> Result<ureq::Body, Failure>;
}

#[cfg(feature = "gcp_kms_keysource")]
impl Fetch for ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    fn fetch(self) -> Result<ureq::Body, Failure> {
        answered(self.call())
    }
}

/// Sending a request built from an agent [`VettedDestination::agent`] handed out, and
/// drawing the line between a result and a refusal: a 4xx or 5xx is a [`Failure::Status`].
///
/// The agent answers every status as a response, so a caller reads a refusal's body under
/// its own bound. A 3xx is not on the failure side: no agent follows a redirect, so one
/// reaches its caller as a body, which that caller parses or refuses.
#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
pub(crate) trait FetchWith {
    /// The request as built, carrying `body`.
    fn fetch_with(self, body: &[u8]) -> Result<ureq::Body, Failure>;
}

#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
impl FetchWith for ureq::RequestBuilder<ureq::typestate::WithBody> {
    fn fetch_with(self, body: &[u8]) -> Result<ureq::Body, Failure> {
        answered(self.send(body))
    }
}

#[cfg(any(
    feature = "online_ocsp",
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource"
))]
fn answered(
    outcome: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::Body, Failure> {
    let response = outcome.map_err(Failure::Transport)?;
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        return Err(Failure::Status(status.as_u16(), Box::new(response)));
    }
    Ok(response.into_body())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client does not chase a `Location:` — for any provenance, and whoever answered.
    ///
    /// A redirect names an authority nothing here vetted, chosen by the responder. On a
    /// credential path that is the whole attack: the guard saw the first URL and no other.
    /// The vetted responder below answers `302` pointing at a second listener; the agent
    /// must hand the redirect back as the response and never connect to the second.
    #[test]
    fn an_agent_does_not_follow_a_redirect_and_never_reaches_the_second_authority() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let elsewhere = TcpListener::bind("127.0.0.1:0").expect("bind the redirect target");
        let elsewhere_port = elsewhere.local_addr().expect("addr").port();
        let reached = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = elsewhere.accept() {
                flag.store(true, Ordering::SeqCst);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let responder = TcpListener::bind("127.0.0.1:0").expect("bind the vetted responder");
        let responder_port = responder.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = responder.accept() {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere_port}/\r\n\
                         Content-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
        });

        let destination =
            VettedDestination::operator_configured(format!("http://127.0.0.1:{responder_port}/"))
                .expect("a loopback http destination is one an operator may configure");
        let outcome = destination
            .agent(Duration::from_secs(5))
            .post(destination.url())
            .config()
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .send("");
        assert_eq!(
            outcome.map(|response| response.status().as_u16()).ok(),
            Some(302),
            "the responder's own redirect must be what the caller sees"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !reached.load(Ordering::SeqCst),
            "the authority named by the redirect was connected to"
        );
    }

    /// A certificate-derived agent installs the resolved-address vetting; an
    /// operator-configured one does not.
    ///
    /// The destination is built through the owner's private fields, so the literal-address
    /// guard in the constructor cannot refuse the loopback listener first: the only thing
    /// left between the agent and the listener is the resolver the provenance selects.
    #[test]
    fn a_certificate_derived_agent_never_connects_to_an_address_its_resolver_refused() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        fn listener_was_reached(provenance: Provenance) -> bool {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind the listener");
            let port = listener.local_addr().expect("addr").port();
            let reached = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&reached);
            std::thread::spawn(move || {
                if listener.accept().is_ok() {
                    flag.store(true, Ordering::SeqCst);
                }
            });
            let destination = VettedDestination {
                url: format!("http://127.0.0.1:{port}/"),
                provenance,
            };
            let _ = destination
                .agent(Duration::from_secs(5))
                .post(destination.url())
                .config()
                .timeout_global(Some(Duration::from_secs(2)))
                .build()
                .send("");
            std::thread::sleep(Duration::from_millis(200));
            reached.load(Ordering::SeqCst)
        }

        assert!(
            listener_was_reached(Provenance::OperatorConfigured),
            "the operator-configured agent must reach a loopback listener"
        );
        assert!(
            !listener_was_reached(Provenance::CertificateDerived),
            "the certificate-derived agent connected to an address its resolver refuses"
        );
    }

    /// The agent's https is the proxy's own connector, end to end through a request.
    ///
    /// `public_roots` proves the connector refuses a private CA when handed a socket. This
    /// proves the agent `agent` hands out refuses one end to end, through a request, as an
    /// I/O error carrying rustls's `UnknownIssuer`.
    ///
    /// It does not tell the proxy's connector from a TLS of ureq's own: ureq's rustls
    /// connector would run first in the chain and report the same refusal the same way, and
    /// with ureq built with `rustls` this stays green. That ureq has no TLS of its own, so
    /// the connector is the only TLS here, is `public_roots::tests::ureq_alone_speaks_no_tls`.
    #[test]
    fn an_agents_https_is_authenticated_by_the_proxys_own_connector() {
        let (_ca, leaf, key) = super::super::public_roots::tests::private_pki();
        let port = super::super::public_roots::tests::serve(leaf, key);
        let destination =
            VettedDestination::operator_configured(format!("https://localhost:{port}/"))
                .expect("a loopback https destination is one an operator may configure");
        let refused = destination
            .agent(Duration::from_secs(5))
            .post(destination.url())
            .send("")
            .expect_err("a server under a private CA must be refused");
        let ureq::Error::Io(io) = &refused else {
            panic!("https was not handled by the proxy's connector: {refused:?}");
        };
        let cause = io
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>());
        assert_eq!(
            cause,
            Some(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )),
            "refused for the wrong reason: {refused}"
        );
    }

    /// The bound belongs to the agent: a request that sets no timeout of its own still returns.
    #[test]
    fn an_agent_bounds_a_request_that_sets_no_timeout_of_its_own() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the silent listener");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(30));
                drop(stream);
            }
        });

        let destination =
            VettedDestination::operator_configured(format!("http://127.0.0.1:{port}/"))
                .expect("a loopback http destination is one an operator may configure");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let outcome = destination
                .agent(Duration::from_millis(300))
                .post(destination.url())
                .send("");
            let _ = tx.send(outcome);
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the agent's own bound must end a request that sets none");
        assert!(
            outcome.is_err(),
            "a listener that never answers must not yield a response"
        );
    }
}
