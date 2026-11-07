//! ONLINE client-certificate revocation via OCSP (#4030, Phase 7,
//! ADR-MCPS-019) — compiled ONLY under the non-default `online_ocsp` feature.
//!
//! The proxy asks the verified client leaf's OCSP responder (RFC 6960) whether it is
//! revoked at connection time, before the request reaches the inner server, so a
//! compromised credential is refused without waiting for a CRL update and restart.
//!
//! # Design
//!
//! A per-connection fail-closed rejection hook, a sibling of
//! `tls::cert_lifetime_rejection`: it runs after the mTLS handshake (the leaf is already
//! chain-verified) and before the handler. A transport error, parse error, trust failure
//! or `Unknown` status all deny; the checker takes no policy input that could admit one.
//!
//! The checker is dormant: no validated deployment enables the online half (THM-0013), and
//! its fetch is a blocking one. The fetch timeout bounds connect, send and the body read; it
//! does NOT bound name resolution, which `ureq` does not interrupt, so a hostile responder
//! hostname can hold a serving thread for the resolver's own limit. Bounding resolution is
//! the async OCSP follow-up's, not this module's.
//!
//! The deterministic pieces — responder-URL extraction, status mapping, the trust
//! pipeline — are small functions the unit tests exercise with no network.
//!
//! # CertID hash
//!
//! CertIDs are built with **SHA-256** (`sha2::Sha256`). The responder MUST be configured to
//! answer SHA-256 CertIDs; an OpenSSL test responder does so with `openssl ocsp ... -sha256`
//! (see `tests/ocsp_e2e_test.rs`).
//!
//! # Issuer binding
//!
//! `check` takes the issuer as an argument, and the CertID, the signer candidate and the
//! responder identity are all measured against it. [`signer::leaf_is_issued_by`] therefore refuses
//! an issuer that did not sign the leaf, so those checks run against the key that issued the
//! handshake-verified leaf and not against whatever a peer presented after it.
//!
//! # Responder-response trust chain (#4063 / MCPS-088, closes #4030)
//!
//! A `Good` admits the client, so RFC 6960 §3.2 requires the response be TRUSTED before its
//! status is acted on. This module runs the full chain BEFORE mapping a status and fails
//! CLOSED on any gap:
//!
//!   1. **Responder signature** — verified over the DER of `tbs_response_data`,
//!      algorithm-agnostically (RSA PKCS#1 v1.5 SHA-256/384/512, ECDSA P-256/P-384, Ed25519,
//!      via `x509-parser`'s `ring`-backed verifier). The signer is EITHER the issuer OR a
//!      delegated responder certificate in `basic.certs` that is in its validity window,
//!      issuer-signed, and carries the `id-kp-OCSPSigning` EKU and `id-pkix-ocsp-nocheck`,
//!      is not a CA and, when it states key usage, permits `digitalSignature`. See
//!      [`verify_responder_signature`] and [`delegated_responder_is_valid`].
//!   2. **Responder identity** — `responder_id` (byName or byKey) must match the signer from
//!      (1). See [`signer::responder_id_matches`].
//!   3. **Nonce** — the request carries a 16-byte CSPRNG nonce; a responder that echoes one
//!      MUST echo ours. See [`freshness::nonce_ok`].
//!   4. **CertID binding** — exactly one `SingleResponse` must bind to the CertID we
//!      requested; none, or more than one, is refused. See [`cert_id::select_matching_single_response`].
//!   5. **Freshness** — `now >= thisUpdate - skew` and `now <= upper + skew`, where `upper`
//!      is `nextUpdate` capped at `thisUpdate + max_response_age`, so a response omitting
//!      `nextUpdate` cannot be replayed indefinitely. See [`freshness::accepted_until`].
//!
//! The answer that comes out carries the end of its own acceptance window, so possession
//! means "a verified responder said this, valid until T": [`OcspChecker::allows`] refuses an
//! answer past it.

use std::time::Duration;
use std::time::SystemTime;

use x509_ocsp::OcspResponseStatus;

use crate::outbound_fetch::VettedDestination;

mod cert_id;
mod delegated_responder;
mod fetch;
mod freshness;
mod issuer;
mod pipeline;
mod request;
mod sha1;
mod signer;

use freshness::system_time_to_unix;
use issuer::leaf_is_issued_by;
use pipeline::verify_and_map_response;
use request::extract_ocsp_responder_url;
use request::SentRequest;

/// The default HTTP fetch timeout: a per-request deadline over connect, send and the body
/// read, after which the check fails closed. It does not cover DNS resolution, which `ureq`
/// does not interrupt.
const DEFAULT_OCSP_TIMEOUT: Duration = Duration::from_secs(5);

/// What a VERIFIED responder said about the client leaf certificate.
///
/// The deterministic mapping of the OCSP `CertStatus` CHOICE, and nothing more: it is not
/// an admission decision, and on its own it is not evidence that anything was verified. A
/// value of this type is only meaningful inside a [`TrustedRevocationAnswer`], which is
/// what makes it earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRevocationStatus {
    /// The responder asserts the certificate is NOT revoked (`good`).
    Good,
    /// The responder asserts the certificate IS revoked (`revoked`).
    Revoked,
    /// The responder itself does not know the certificate's status (`unknown`).
    ///
    /// This is a RESPONDER VERDICT and is deliberately distinct from
    /// [`RevocationEvidence::NotEstablished`] — a responder that answers "I do not know"
    /// has been reached, verified, and has spoken, and a fetch that never happened has
    /// not. Both fail closed, and conflating them would make the audit trail say the
    /// responder answered when nothing did.
    Unknown,
}

/// The conclusion the RFC 6960 §3.2 trust chain reached — and the ONLY way to speak one.
///
/// The representation is private and [`verify_and_map_response`] is its sole producer, so
/// possession of one means all five checks ran: the responder signature verified against
/// the issuer or a delegated `id-kp-OCSPSigning` responder, the `responder_id` matched that
/// signer, a present nonce echoed ours, a `SingleResponse` bound to the CertID we asked
/// about, and that response was fresh. There is no constructor taking a status.
///
/// It also carries the end of its own acceptance window, as a `Duration` since the Unix
/// epoch: a freshness proof taken at T is not an admission token forever. It is not `Copy`,
/// so the dated value is handed on rather than duplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRevocationAnswer {
    status: CertRevocationStatus,
    valid_until: Duration,
}

impl TrustedRevocationAnswer {
    /// What the verified responder said.
    pub fn status(&self) -> CertRevocationStatus {
        self.status
    }

    /// Whether this answer admits the certificate at `now`: it said `Good` and `now` is
    /// still inside the window it was accepted for.
    fn admits_at(&self, now: SystemTime) -> bool {
        self.status == CertRevocationStatus::Good
            && system_time_to_unix(now).is_some_and(|now| now <= self.valid_until)
    }

    /// A verified answer, for a test whose subject is the POLICY rather than the chain.
    ///
    /// `#[cfg(test)]`. The policy — only a `Good` inside its window admits — is a different
    /// proposition from "the chain ran", and a test of the first should not have to mint a
    /// signed OCSP response to state it. It compiles to nothing outside the test build, so
    /// the seal holds against every production path and against every other crate.
    #[cfg(test)]
    fn answered(status: CertRevocationStatus, valid_until: Duration) -> Self {
        TrustedRevocationAnswer {
            status,
            valid_until,
        }
    }
}

/// What this proxy knows about a certificate's revocation, and whether it EARNED it.
///
/// The two are not the same fact and the census asked for them to stop being the same
/// value. A responder that answered `unknown` was reached and verified; a check with no
/// responder URL, or one whose destination the outbound guard refused, reached nothing.
/// Both deny — that is the POLICY, and it is [`OcspChecker::allows`]'s — but only one of
/// them is a statement about the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationEvidence {
    /// A verified responder answered. See [`TrustedRevocationAnswer`].
    Answered(TrustedRevocationAnswer),
    /// No trusted result could be established locally. Never a responder verdict.
    NotEstablished(NotEstablished),
}

/// Why no trusted revocation result could be established.
///
/// Local facts, every one of them: nothing here is anything a responder said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEstablished {
    /// The leaf carries no AIA OCSP URL and no operator override was configured, so there
    /// was nowhere to ask.
    NoResponderConfigured,
    /// A responder URL existed and the outbound-fetch guard refused it — a certificate
    /// naming a private address or a scheme outside `http`/`https`. See
    /// [`crate::outbound_fetch`].
    DestinationRefused,
}

/// Errors performing an online OCSP check. Every variant is a fail-closed
/// condition: the connection is rejected.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    /// A certificate (leaf or issuer) could not be decoded from DER.
    #[error("invalid certificate DER: {0}")]
    BadCertificate(String),
    /// The OCSP request could not be built or DER-encoded.
    #[error("OCSP request build failed: {0}")]
    BuildRequest(String),
    /// The HTTP POST to the responder failed (connect/timeout/transport/status).
    #[error("OCSP responder HTTP error: {0}")]
    Http(String),
    /// The responder's HTTP body could not be read.
    #[error("OCSP response read error: {0}")]
    ReadBody(String),
    /// The response could not be decoded as an `OCSPResponse`.
    #[error("OCSP response decode failed: {0}")]
    DecodeResponse(String),
    /// The responder returned a non-`successful` `OCSPResponseStatus`.
    #[error("OCSP responder returned non-successful status: {0:?}")]
    ResponderStatus(OcspResponseStatus),
    /// A `successful` response carried no `responseBytes`, or they were not a
    /// `BasicOCSPResponse`, or it held no `SingleResponse`.
    #[error("OCSP response malformed: {0}")]
    MalformedResponse(String),
    /// The responder's signature over `tbs_response_data` could not be verified
    /// against the issuer or a valid delegated responder certificate. This is the
    /// RFC 6960 §3.2 trust failure — fail CLOSED.
    #[error("OCSP responder signature not verified: {0}")]
    SignatureNotVerified(String),
    /// The `responder_id` did not match the certificate whose key verified the
    /// signature (the responder asserted an identity it did not sign as).
    #[error("OCSP responder identity mismatch: {0}")]
    ResponderIdentityMismatch(String),
    /// No `SingleResponse` in the response answered the CertID we requested, so
    /// the response carries no evidence about THIS certificate.
    #[error("OCSP response has no SingleResponse for the requested CertID")]
    CertIdMismatch,
    /// The response is stale (`now > nextUpdate + skew`) or not yet valid
    /// (`now < thisUpdate - skew`).
    #[error("OCSP response not fresh: {0}")]
    NotFresh(String),
    /// The responder echoed a nonce that did not equal the request nonce — a
    /// replayed or substituted response.
    #[error("OCSP response nonce mismatch")]
    NonceMismatch,
}

/// Performs an online OCSP revocation check for a verified client leaf
/// certificate against its issuer. Holds only configuration; it is cheap to
/// clone and carries no network state between calls.
///
/// `Debug` is written by hand: the configured responder URL may carry userinfo
/// credentials, and `ServerOptions` derives `Debug` over this type.
#[derive(Clone)]
pub struct OcspChecker {
    /// An explicit responder URL that OVERRIDES the leaf's AIA OCSP URL. `None`
    /// means "use the AIA URL from the leaf" (and a leaf without one establishes nothing).
    ///
    /// Held as the raw string rather than a [`VettedDestination`]: an override that fails
    /// the scheme allowlist must fail the connection being checked, not construction at
    /// startup for a deployment that may never reach this code.
    responder_url_override: Option<String>,
    /// The HTTP fetch timeout (see [`DEFAULT_OCSP_TIMEOUT`]).
    timeout: Duration,
}

impl std::fmt::Debug for OcspChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspChecker")
            .field("responder_override", &self.responder_url_override.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OcspChecker {
    /// Build a checker. `responder_url_override` (the `--ocsp-responder-url`
    /// AIA override) is used verbatim when set; otherwise the responder URL is
    /// read from the leaf's AIA OCSP entry. The timeout defaults to
    /// [`DEFAULT_OCSP_TIMEOUT`]. There is no fail-open posture to select.
    pub fn new(responder_url_override: Option<String>) -> Self {
        OcspChecker {
            responder_url_override,
            timeout: DEFAULT_OCSP_TIMEOUT,
        }
    }

    /// Perform the full online check for `leaf_der` against `issuer_der`:
    ///
    ///   a. resolve the responder URL (override, else the leaf's AIA OCSP URL;
    ///      none, or one the outbound guard refuses, establishes nothing);
    ///   b. require that `issuer_der` signed `leaf_der`;
    ///   c. build a SHA-256 CertID OCSP request carrying a fresh nonce;
    ///   d. POST it to the responder, reading the body (any transport/timeout
    ///      error → `Err`);
    ///   e. run the §3.2 trust chain over the response.
    ///
    /// Transport, codec and trust failures are `Err(OcspError)`. The admit/deny
    /// decision is [`OcspChecker::allows`].
    pub fn check(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<RevocationEvidence, OcspError> {
        // The guard is `crate::outbound_fetch`'s and it runs at CONSTRUCTION: there is no
        // way to reach `fetch::post` with a destination that did not pass the guard its
        // provenance requires. The reason nothing was established is decided there, once.
        let destination = match self.responder_destination(leaf_der) {
            Ok(destination) => destination,
            Err(reason) => return Ok(RevocationEvidence::NotEstablished(reason)),
        };
        if !leaf_is_issued_by(leaf_der, issuer_der)? {
            return Err(OcspError::BadCertificate(
                "leaf is not signed by the supplied issuer".into(),
            ));
        }

        // A fresh per-request CSPRNG nonce binds the response to THIS request: a
        // captured/replayed response carries a stale (mismatched) nonce and is
        // rejected (RFC 6960 §4.4.1 / RFC 8954).
        let sent = SentRequest::new(leaf_der, issuer_der)?;
        let response_der = fetch::post(&destination, self.timeout, sent.der())?;
        verify_and_map_response(&response_der, &sent, SystemTime::now())
            .map(RevocationEvidence::Answered)
    }

    /// The destination to fetch from, guarded according to where it came from — or why
    /// there is none.
    ///
    /// The configured override wins and is OPERATOR-CONFIGURED; otherwise the AIA OCSP URL
    /// is read from the leaf and is CERTIFICATE-DERIVED. Which constructor is called is the
    /// whole of the provenance decision, and it is made HERE, once — the guard each one
    /// applies belongs to [`crate::outbound_fetch`] and this module cannot choose between
    /// them after the fact. Pure (no network) and unit-tested.
    fn responder_destination(&self, leaf_der: &[u8]) -> Result<VettedDestination, NotEstablished> {
        if let Some(url) = &self.responder_url_override {
            return VettedDestination::operator_configured(url.clone())
                .ok_or(NotEstablished::DestinationRefused);
        }
        let url =
            extract_ocsp_responder_url(leaf_der).ok_or(NotEstablished::NoResponderConfigured)?;
        VettedDestination::certificate_derived(url).ok_or(NotEstablished::DestinationRefused)
    }

    /// The admit/deny decision for the evidence a check produced, at `now`.
    ///
    /// Only a `Good` answer still inside its own acceptance window admits. `Revoked`, a
    /// responder that said `unknown`, an answer past its window, and every reason no
    /// trusted result was established all deny.
    ///
    /// It takes [`RevocationEvidence`], not a status: a `Good` that nothing earned cannot
    /// be handed to this function, because there is no way to make one.
    /// Returns `true` to ALLOW the connection, `false` to REJECT it.
    pub fn allows(&self, evidence: RevocationEvidence, now: SystemTime) -> bool {
        match evidence {
            RevocationEvidence::Answered(answer) => answer.admits_at(now),
            RevocationEvidence::NotEstablished(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CertRevocationStatus;
    use super::NotEstablished;
    use super::OcspChecker;
    use super::OcspError;
    use super::RevocationEvidence;
    use super::TrustedRevocationAnswer;
    use crate::ocsp::pipeline::tests::at;
    use crate::ocsp::pipeline::tests::Ymd;
    use crate::ocsp::request::tests::mint_leaf_with_aia;
    use crate::ocsp::signer::tests::mint_issuer;

    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use rcgen::CertificateParams;
    use rcgen::KeyPair;

    /// The end of an answer's window, far beyond any `now` the policy tests use.
    pub(super) const FAR_FUTURE: Duration = Duration::from_secs(u64::MAX / 4);

    /// `evidence` of an answer with `status`, valid far beyond any `now` the policy tests use.
    pub(super) fn answered(status: CertRevocationStatus) -> RevocationEvidence {
        RevocationEvidence::Answered(TrustedRevocationAnswer::answered(status, FAR_FUTURE))
    }

    #[test]
    fn checker_allows_methods_match_policy() {
        let checker = OcspChecker::new(None);
        let now = at(Ymd(2024, 1, 1));
        assert!(checker.allows(answered(CertRevocationStatus::Good), now));
        assert!(!checker.allows(answered(CertRevocationStatus::Revoked), now));
        assert!(!checker.allows(answered(CertRevocationStatus::Unknown), now));
        for reason in [
            NotEstablished::NoResponderConfigured,
            NotEstablished::DestinationRefused,
        ] {
            assert!(
                !checker.allows(RevocationEvidence::NotEstablished(reason), now),
                "{reason:?} establishes nothing and must deny"
            );
        }
    }

    /// Possession of an answer is not an admission token forever: the answer carries the
    /// end of the window it was accepted for, and `allows` refuses it past that.
    #[test]
    fn an_answer_past_its_own_freshness_bound_is_not_admitted() {
        let checker = OcspChecker::new(None);
        let bound = Duration::from_secs(1_700_000_000);
        let evidence = || {
            RevocationEvidence::Answered(TrustedRevocationAnswer::answered(
                CertRevocationStatus::Good,
                bound,
            ))
        };
        assert!(
            checker.allows(evidence(), UNIX_EPOCH + bound),
            "at the bound"
        );
        assert!(
            !checker.allows(evidence(), UNIX_EPOCH + bound + Duration::from_secs(1)),
            "one second past the bound"
        );
    }

    /// A credential in the configured responder URL reaches no operational text: not the
    /// checker's `Debug`, which `ServerOptions` derives over. The transport error's rendering
    /// is `fetch`'s.
    #[test]
    fn a_credential_in_the_responder_url_is_not_in_the_checkers_debug() {
        const URL: &str = "http://user:s3cret@127.0.0.1:1/ocsp";
        let checker = OcspChecker::new(Some(URL.to_string()));
        let debug = format!("{checker:?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(debug.contains("responder_override: true"), "{debug}");
    }

    /// `ServerOptions` with the checker `checker` and a legal credential window.
    fn server_options(checker: Option<OcspChecker>) -> crate::tls::ServerOptions {
        let window = crate::config_state::ClientCredentialWindow::new(
            Duration::from_secs(3600),
            Duration::from_secs(300),
        )
        .expect("a legal credential window");
        crate::tls::ServerOptions {
            ocsp_checker: checker,
            ..crate::tls::ServerOptions::new(
                window,
                crate::config_state::RequestTarget::new("https://localhost/")
                    .expect("an absolute target"),
            )
        }
    }

    /// The per-connection admit decision over the checker: only a verified `Good` admits, so a
    /// chain the checker cannot establish anything about is rejected, and no checker rejects
    /// nothing.
    #[test]
    fn the_connection_hook_rejects_what_the_checker_cannot_establish() {
        use crate::tls::ocsp_rejection_for_chain;
        let options = server_options(Some(OcspChecker::new(None)));
        let request = b"{\"id\":1}";
        let leaf: &[u8] = b"leaf";
        assert!(
            ocsp_rejection_for_chain(&[leaf], &options, request).is_some(),
            "a leaf with no chained issuer is rejected"
        );
        // No override and no AIA URL on the leaf: nothing is asked, so nothing is admitted.
        let chain: [&[u8]; 2] = [b"leaf", b"issuer"];
        assert!(
            ocsp_rejection_for_chain(&chain, &options, request).is_some(),
            "a check that establishes nothing is rejected"
        );
        assert!(
            ocsp_rejection_for_chain(&chain, &server_options(None), request).is_none(),
            "without a checker nothing is rejected"
        );
    }

    /// The checker only asks about a leaf the supplied issuer issued: the CertID, the
    /// signer candidate and the responder identity are all measured against that issuer.
    #[test]
    fn check_refuses_an_issuer_that_did_not_sign_the_leaf() {
        let leaf = mint_leaf_with_aia("http://127.0.0.1:1/ocsp");
        let (unrelated_issuer, _) = mint_issuer();
        let checker = OcspChecker::new(Some("http://127.0.0.1:1/ocsp".to_string()));
        let result = checker.check(&leaf, &unrelated_issuer);
        assert!(
            matches!(result, Err(OcspError::BadCertificate(_))),
            "an issuer that did not sign the leaf must be refused before any request: {result:?}"
        );
    }

    // ADR-MCPS-023 §A1 (v0.9, MCPS-58): an OCSP check that cannot run because the
    // leaf carries no responder URL (no AIA, no operator override) yields an
    // indeterminate result — `check` returns Unknown (fail closed), NEVER Good. A
    // revocation check that never happened must not be recorded as a successful /
    // "not revoked" check. The no-URL path returns before any network I/O, so this
    // is fully offline.
    #[test]
    fn check_without_responder_url_establishes_nothing_and_is_not_good() {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let leaf = params.self_signed(&key).expect("self-signed").der().clone();
        let checker = OcspChecker::new(None); // no override
        let evidence = checker
            .check(leaf.as_ref(), leaf.as_ref())
            .expect("the no-responder-URL path returns without network I/O");
        // NOT a responder verdict of `Unknown` — nothing was asked. Keeping the two apart
        // is the point: a check that could not run must not be recorded as a responder
        // saying anything, and it must never be `Good`.
        assert_eq!(
            evidence,
            RevocationEvidence::NotEstablished(NotEstablished::NoResponderConfigured),
        );
        assert!(
            !checker.allows(evidence, SystemTime::now()),
            "a check that could not run must deny"
        );
    }

    #[test]
    fn check_with_no_url_is_unknown() {
        // No override and a leaf without AIA → check() short-circuits to Unknown
        // (no network performed).
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let leaf = params.self_signed(&key).expect("self-signed");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        let status = checker
            .check(leaf.der().as_ref(), &issuer_der)
            .expect("the no-URL check returns without network I/O");
        assert_eq!(
            status,
            RevocationEvidence::NotEstablished(NotEstablished::NoResponderConfigured)
        );
    }

    // === #4078 (MCP-RE-MED-5, M14) — AIA responder-URL SSRF guard =============
    //
    // The AIA OCSP responder URL is taken VERBATIM from the attacker-influenced
    // leaf certificate and (pre-fix) fetched with no scheme/SSRF guard. A hostile
    // leaf can point the proxy at `file://`, `gopher://`, or an internal/link-local
    // host (169.254/16, 127/8, ::1, 10/8, 172.16/12, 192.168/16, metadata
    // endpoints) → SSRF. The guard must reject such a responder URL BEFORE any
    // network fetch, failing CLOSED (deny) exactly as a
    // missing AIA URL does. The operator-supplied `--ocsp-responder-url` override
    // is scheme-checked (http/https only) but, by design, NOT subject to the
    // private-IP block (an operator may legitimately run an internal responder).

    /// Check a leaf whose ONLY AIA OCSP URL is `aia_url` against a checker with no
    /// override: the destination guard refuses it, so `check` returns without any fetch.
    /// Were the guard absent the path would POST (slowly, for an unroutable port) and
    /// return `Err(Http(..))`, so an `Ok` proves no fetch occurred.
    fn check_refuses_cert_aia(aia_url: &str) -> RevocationEvidence {
        let leaf = mint_leaf_with_aia(aia_url);
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        let evidence = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("an unsafe AIA URL fails closed, not Err");
        assert_eq!(
            evidence,
            RevocationEvidence::NotEstablished(NotEstablished::DestinationRefused),
            "{aia_url} must be refused pre-fetch"
        );
        evidence
    }

    /// A disallowed scheme on the CERT-supplied AIA URL must be rejected before
    /// any fetch. The destination was refused, which is a LOCAL fact and not something a
    /// responder said. `file://` is the canonical SSRF/file-read vector.
    #[test]
    fn check_rejects_cert_aia_file_scheme_before_fetch() {
        let evidence = check_refuses_cert_aia("file:///etc/passwd");
        assert!(
            !OcspChecker::new(None).allows(evidence, SystemTime::now()),
            "an unestablished result must deny"
        );
    }

    /// A loopback host on the CERT-supplied AIA URL is an SSRF vector and must be
    /// rejected pre-fetch (fail closed).
    #[test]
    fn check_rejects_cert_aia_loopback_host_before_fetch() {
        check_refuses_cert_aia("http://127.0.0.1:1/ocsp");
    }

    /// `localhost` (a hostname, not a literal IP) is the loopback name and must
    /// likewise be rejected on the cert-derived path.
    #[test]
    fn check_rejects_cert_aia_localhost_before_fetch() {
        check_refuses_cert_aia("http://localhost:1/ocsp");
    }
}
