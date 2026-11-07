//! The RFC 6960 §3.2 response-trust pipeline: the one place an OCSP response becomes a
//! [`TrustedRevocationAnswer`].
//!
//! The checks are conjuncts of ONE argument — a `Good` admits the client, so the response must
//! be trusted before its status is acted on — and they run here, in order, in one function so
//! that the order is what the reader sees. Each check is a named predicate in its own
//! module: [`super::signer`] (signature and responder identity), [`super::freshness`] (nonce
//! and window) and [`super::cert_id`] (binding to the certificate asked about).

use std::time::SystemTime;

use der::Decode;
use x509_ocsp::BasicOcspResponse;
use x509_ocsp::CertStatus;
use x509_ocsp::OcspResponse;
use x509_ocsp::OcspResponseStatus;

use super::cert_id::select_matching_single_response;
use super::freshness::accepted_until;
use super::freshness::nonce_ok;
use super::request::SentRequest;
use super::signer::responder_id_matches;
use super::signer::verify_responder_signature;
use super::CertRevocationStatus;
use super::OcspError;
use super::TrustedRevocationAnswer;

/// Map an OCSP `CertStatus` CHOICE to a [`CertRevocationStatus`]. Pure and
/// unit-tested. `good` → `Good`, `revoked` → `Revoked`, `unknown` → `Unknown`.
fn map_cert_status(status: &CertStatus) -> CertRevocationStatus {
    match status {
        CertStatus::Good(_) => CertRevocationStatus::Good,
        CertStatus::Revoked(_) => CertRevocationStatus::Revoked,
        CertStatus::Unknown(_) => CertRevocationStatus::Unknown,
    }
}

/// The RFC 6960 §3.2 response-trust pipeline. Decode `response_der`, require a
/// `Successful` status, parse the `BasicOCSPResponse`, then — BEFORE trusting any
/// status — verify in order: (1) the responder signature over
/// `tbs_response_data` against the issuer or a delegated `id-kp-OCSPSigning`
/// responder cert; (2) the `responder_id` matches that signer; (3) the request
/// `nonce` echoes (when present); (4) a `SingleResponse` binds to the CertID of the
/// request `sent`; (5) that response is fresh at `now`. Only then is its
/// `cert_status` mapped. ANY failure is an `Err`, which the caller treats as
/// fail-closed (deny). Pure (no network), unit-tested.
pub(super) fn verify_and_map_response(
    response_der: &[u8],
    sent: &SentRequest,
    now: SystemTime,
) -> Result<TrustedRevocationAnswer, OcspError> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|e| OcspError::DecodeResponse(e.to_string()))?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(OcspError::ResponderStatus(response.response_status));
    }
    let response_bytes = response
        .response_bytes
        .ok_or_else(|| OcspError::MalformedResponse("successful response with no bytes".into()))?;
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|e| OcspError::MalformedResponse(format!("not a BasicOCSPResponse: {e}")))?;

    // (1) responder signature + (2) responder identity, against the issuer or a
    // delegated responder cert. Returns the cert whose key verified the response
    // so the identity check can be made against the SAME key.
    let signer = verify_responder_signature(&basic, sent.issuer_der(), now)?;
    if !responder_id_matches(&basic.tbs_response_data.responder_id, &signer) {
        return Err(OcspError::ResponderIdentityMismatch(
            "responder_id does not match the signing certificate".into(),
        ));
    }

    // (3) nonce: if the responder echoed a nonce it MUST equal ours. (A responder
    // that omits the nonce entirely is permitted by RFC 6960 — many do not honor
    // nonces — but a PRESENT, MISMATCHED nonce is a replay/substitution.)
    if !nonce_ok(&basic, sent.nonce()) {
        return Err(OcspError::NonceMismatch);
    }

    // (4) CertID binding: select the one SingleResponse that answers OUR cert.
    let single =
        select_matching_single_response(&basic, sent.cert_id()).ok_or(OcspError::CertIdMismatch)?;

    // (5) freshness of the selected response, which also yields the end of its window.
    let Some(valid_until) = accepted_until(single, now) else {
        return Err(OcspError::NotFresh(
            "response not fresh: now outside [thisUpdate - skew, upper + skew], \
             where upper = min(nextUpdate, thisUpdate + max_response_age)"
                .into(),
        ));
    };

    // The ONLY construction of a `TrustedRevocationAnswer` in the crate, and it is here,
    // after all five checks. Everything above this line is what possession of the returned
    // value means.
    Ok(TrustedRevocationAnswer {
        status: map_cert_status(&single.cert_status),
        valid_until,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::map_cert_status;
    use super::verify_and_map_response;
    use crate::ocsp::request::tests::mint_leaf_with_aia;
    use crate::ocsp::signer::tests::mint_issuer;
    use crate::ocsp::tests::answered;
    use crate::ocsp::CertRevocationStatus;
    use crate::ocsp::OcspChecker;
    use crate::ocsp::OcspError;
    use crate::ocsp::SentRequest;
    use crate::ocsp::TrustedRevocationAnswer;

    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use crate::ocsp::RevocationEvidence;
    use der::asn1::BitString;
    use der::Decode;
    use der::Encode;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use rcgen::PKCS_ED25519;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::ext::AsExtension;
    use x509_cert::ext::Extension;
    use x509_cert::Certificate;
    use x509_ocsp::ext::Nonce;
    use x509_ocsp::BasicOcspResponse;
    use x509_ocsp::CertId;
    use x509_ocsp::CertStatus;
    use x509_ocsp::OcspGeneralizedTime;
    use x509_ocsp::OcspResponse;
    use x509_ocsp::ResponderId;
    use x509_ocsp::ResponseData;
    use x509_ocsp::SingleResponse;
    use x509_ocsp::Version;

    /// A calendar day (year, month, day) at 00:00:00 UTC.
    #[derive(Clone, Copy)]
    pub(in crate::ocsp) struct Ymd(
        pub(in crate::ocsp) u16,
        pub(in crate::ocsp) u8,
        pub(in crate::ocsp) u8,
    );

    impl Ymd {
        fn date_time(self) -> der::DateTime {
            der::DateTime::new(self.0, self.1, self.2, 0, 0, 0).expect("datetime")
        }
    }

    /// A GeneralizedTime fixture for `day`.
    pub(in crate::ocsp) fn gtime(day: Ymd) -> OcspGeneralizedTime {
        OcspGeneralizedTime::from(day.date_time())
    }

    /// SystemTime at `day` (for injected `now`).
    pub(in crate::ocsp) fn at(day: Ymd) -> SystemTime {
        UNIX_EPOCH + day.date_time().unix_duration()
    }

    /// The request nonce the response-verification tests send unless they are about the nonce.
    pub(in crate::ocsp) const REQUEST_NONCE: &[u8] = b"req-nonce";

    /// The request a response is built to answer: the issuer and the leaf asked about.
    pub(in crate::ocsp) struct Target<'a> {
        pub(in crate::ocsp) issuer_der: &'a [u8],
        pub(in crate::ocsp) leaf_der: &'a [u8],
    }

    impl Target<'_> {
        /// The request for this target carrying `nonce`.
        pub(in crate::ocsp) fn sent(&self, nonce: &[u8]) -> SentRequest {
            SentRequest::with_nonce(self.leaf_der, self.issuer_der, nonce.to_vec())
                .expect("sent request")
        }
    }

    /// Knobs for hand-building an UNSIGNED OCSP response fixture, so each acceptance test
    /// can isolate exactly ONE broken control (wrong CertID, stale, bad nonce, …).
    pub(in crate::ocsp) struct ResponseFixture {
        pub(in crate::ocsp) status: CertStatus,
        /// `None` ⇒ use the CertID derived from `(issuer, leaf)` (the matching
        /// one); `Some(id)` ⇒ a deliberately different CertID (binding test).
        pub(in crate::ocsp) cert_id: Option<CertId>,
        pub(in crate::ocsp) this_update: OcspGeneralizedTime,
        pub(in crate::ocsp) next_update: Option<OcspGeneralizedTime>,
        /// `Some(bytes)` ⇒ echo this nonce in the response extensions.
        pub(in crate::ocsp) echo_nonce: Option<Vec<u8>>,
    }

    impl ResponseFixture {
        /// A `good` response, fresh on 2024-01-01 and good until 2024-01-02, echoing no
        /// nonce, answering the matching CertID: the baseline the tests perturb.
        pub(in crate::ocsp) fn good() -> Self {
            ResponseFixture {
                status: CertStatus::good(),
                cert_id: None,
                this_update: gtime(Ymd(2024, 1, 1)),
                next_update: Some(gtime(Ymd(2024, 1, 2))),
                echo_nonce: None,
            }
        }
    }

    /// An unsigned response built over a fresh issuer and leaf, with both certificates.
    pub(in crate::ocsp) struct Built {
        pub(in crate::ocsp) issuer_der: Vec<u8>,
        pub(in crate::ocsp) leaf_der: Vec<u8>,
        pub(in crate::ocsp) response_der: Vec<u8>,
    }

    impl Built {
        /// The target this response was built for.
        pub(in crate::ocsp) fn target(&self) -> Target<'_> {
            Target {
                issuer_der: &self.issuer_der,
                leaf_der: &self.leaf_der,
            }
        }

        /// Run the production trust pipeline over this response at `now`.
        pub(in crate::ocsp) fn verify(
            &self,
            nonce: &[u8],
            now: SystemTime,
        ) -> Result<TrustedRevocationAnswer, OcspError> {
            verify_and_map_response(&self.response_der, &self.target().sent(nonce), now)
        }

        /// The `BasicOcspResponse` inside this response, for white-box control tests.
        /// (Production code only reaches it via `verify_and_map_response`.)
        pub(in crate::ocsp) fn basic(&self) -> BasicOcspResponse {
            let response = OcspResponse::from_der(&self.response_der).expect("response");
            let bytes = response.response_bytes.expect("bytes");
            BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("basic")
        }
    }

    /// How a response is signed: the signature algorithm OID, the signature bits, and any
    /// certificates carried in `basic.certs`.
    pub(in crate::ocsp) struct Signature {
        pub(in crate::ocsp) alg_oid: &'static str,
        pub(in crate::ocsp) bits: Vec<u8>,
        pub(in crate::ocsp) certs: Option<Vec<Certificate>>,
    }

    /// The extension echoing `nonce` in a response, when there is one to echo.
    fn echoed_nonce_extensions(
        nonce: Option<Vec<u8>>,
        issuer: &Certificate,
    ) -> Option<Vec<Extension>> {
        nonce.map(|bytes| {
            let nonce = Nonce::new(bytes).expect("nonce");
            vec![nonce
                .to_extension(&issuer.tbs_certificate.subject, &[])
                .expect("nonce extension")]
        })
    }

    /// The DER of a successful response around `tbs`, signed per `signature`.
    pub(in crate::ocsp) fn successful_response_der(
        tbs: ResponseData,
        signature: Signature,
    ) -> Vec<u8> {
        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: signature.alg_oid.parse().expect("oid"),
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.bits).expect("bitstring"),
            certs: signature.certs,
        };
        OcspResponse::successful(basic)
            .expect("successful response")
            .to_der()
            .expect("response DER")
    }

    /// Build an unsigned response per `fixture`. The production trust path verifies the
    /// signature with the ring-backed verifier that ships in the `online_ocsp` build, so
    /// an unsigned response is rejected at the signature gate.
    pub(in crate::ocsp) fn build_fixture(fixture: ResponseFixture) -> Built {
        let (issuer_der, _) = mint_issuer();
        let leaf_der = mint_leaf_with_aia("http://ocsp.example.test/r");
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let requested =
            SentRequest::with_nonce(&leaf_der, &issuer_der, Vec::new()).expect("requested");
        let response_cert_id = fixture
            .cert_id
            .unwrap_or_else(|| requested.cert_id().clone());

        let mut single = SingleResponse::new(response_cert_id, fixture.status, fixture.this_update);
        single.next_update = fixture.next_update;

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            produced_at: fixture.this_update,
            responses: vec![single],
            response_extensions: echoed_nonce_extensions(fixture.echo_nonce, &issuer),
        };
        Built {
            issuer_der,
            leaf_der,
            // ecdsa-with-SHA256; the empty signature is what is actually verified.
            response_der: successful_response_der(
                tbs,
                Signature {
                    alg_oid: "1.2.840.10045.4.3.2",
                    bits: Vec::new(),
                    certs: None,
                },
            ),
        }
    }

    /// The revoked CHOICE as a responder states it, revoked on 2023-06-01 for no reason.
    pub(in crate::ocsp) fn revoked_status() -> CertStatus {
        CertStatus::revoked(x509_ocsp::RevokedInfo {
            revocation_time: gtime(Ymd(2023, 6, 1)),
            revocation_reason: None,
        })
    }

    /// An unsigned response fails at the signature gate, before any status is mapped.
    fn assert_refused_at_signature_gate(result: Result<TrustedRevocationAnswer, OcspError>) {
        assert!(
            matches!(result, Err(OcspError::SignatureNotVerified(_))),
            "an unsigned response must be rejected at the signature gate, got {result:?}"
        );
    }

    // === #4063 (MCPS-088) acceptance tests — RFC 6960 §3.2 response trust =====
    //
    // Each asserts that a response which would, under the OLD code, ADMIT a leaf
    // (it returned the raw `cert_status`) is now DENIED because one trust control
    // rejects it. The `online_ocsp` build compiles the real ring-backed verifier,
    // so an unsigned signature is rejected at the signature gate — NOTHING admits
    // without a verified signature. The `mod verify` tests below re-prove the
    // per-control gates END-TO-END with a genuinely signed (Ed25519) response.

    /// ACCEPTANCE 1 — forged/unsigned responder returns Good for a leaf, but the
    /// signature is not verifiable ⇒ DENIED. This is the empty-signature fixture
    /// that the OLD code trusted; it must now fail closed.
    #[test]
    fn acceptance_unsigned_good_is_denied() {
        let built = build_fixture(ResponseFixture::good());
        assert_refused_at_signature_gate(
            built.verify(b"unused-request-nonce", at(Ymd(2024, 1, 1))),
        );
    }

    /// ACCEPTANCE 2 — CertID binding. A response whose SingleResponse answers a
    /// DIFFERENT CertID carries no evidence about our leaf; the pipeline denies it. The
    /// binding gate itself is proven in `cert_id`'s own tests.
    #[test]
    fn acceptance_wrong_certid_is_denied() {
        let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = SentRequest::with_nonce(&other_leaf, &issuer_der, Vec::new())
            .expect("wrong id")
            .cert_id()
            .clone();
        let built = build_fixture(ResponseFixture {
            cert_id: Some(wrong_id),
            ..ResponseFixture::good()
        });
        assert!(built.verify(b"n", at(Ymd(2024, 1, 1))).is_err());
    }

    /// ACCEPTANCE 3 — freshness. A response whose `nextUpdate` is in the past is stale
    /// ⇒ DENIED.
    #[test]
    fn acceptance_stale_response_is_denied() {
        let built = build_fixture(ResponseFixture {
            this_update: gtime(Ymd(2023, 1, 1)),
            next_update: Some(gtime(Ymd(2023, 1, 2))),
            ..ResponseFixture::good()
        });
        // `now` is well past nextUpdate → not fresh.
        assert!(
            built.verify(b"n", at(Ymd(2024, 6, 1))).is_err(),
            "a stale response must be denied"
        );
    }

    /// ACCEPTANCE 4 — nonce. A captured response echoing nonce A, replayed against
    /// a FRESH request nonce B, must be rejected.
    #[test]
    fn acceptance_nonce_mismatch_is_denied() {
        let captured_nonce = b"captured-nonce-AAAA".to_vec();
        let built = build_fixture(ResponseFixture {
            echo_nonce: Some(captured_nonce.clone()),
            ..ResponseFixture::good()
        });
        // Fresh request nonce differs from the echoed one.
        let unique_test_nonce = b"fresh-request-nonce-B".to_vec();
        assert_ne!(captured_nonce, unique_test_nonce);
        assert!(
            built
                .verify(&unique_test_nonce, at(Ymd(2024, 1, 1)))
                .is_err(),
            "a response echoing a stale nonce under a fresh request must be denied"
        );
    }

    /// ACCEPTANCE 5 (status-policy negatives) — Revoked and Unknown both DENY
    /// The positive (signed Good → ADMIT) is the `mod verify`
    /// test below (it needs a real responder signature).
    #[test]
    fn acceptance_revoked_and_unknown_deny() {
        // Pure policy: neither Revoked nor Unknown admits, however fresh.
        let checker = OcspChecker::new(None);
        for status in [CertRevocationStatus::Revoked, CertRevocationStatus::Unknown] {
            assert!(!checker.allows(answered(status), at(Ymd(2024, 1, 1))));
        }
        // An UNSIGNED Revoked/Unknown response is refused at the signature gate,
        // before any status is mapped. Assert that exact outcome: a bare
        // "did not admit" would also be satisfied by an unrelated failure.
        for status in [revoked_status(), CertStatus::unknown()] {
            let built = build_fixture(ResponseFixture {
                status,
                ..ResponseFixture::good()
            });
            assert_refused_at_signature_gate(built.verify(b"n", at(Ymd(2024, 1, 1))));
        }
    }

    #[test]
    fn rejects_non_successful_responder_status() {
        let try_later = OcspResponse::try_later().to_der().expect("try_later DER");
        let (issuer_der, _) = mint_issuer();
        let leaf = mint_leaf_with_aia("http://x/r");
        let target = Target {
            issuer_der: &issuer_der,
            leaf_der: &leaf,
        };
        assert!(
            verify_and_map_response(&try_later, &target.sent(b"n"), at(Ymd(2024, 1, 1))).is_err(),
            "a non-successful OCSP responder status must fail closed"
        );
    }

    #[test]
    fn cert_status_helper_maps_choices() {
        assert_eq!(
            map_cert_status(&CertStatus::good()),
            CertRevocationStatus::Good
        );
        assert_eq!(
            map_cert_status(&revoked_status()),
            CertRevocationStatus::Revoked,
            "a responder's revoked CHOICE must map to Revoked, the only value \
             nothing admits"
        );
        assert_eq!(
            map_cert_status(&CertStatus::unknown()),
            CertRevocationStatus::Unknown
        );
    }

    // === #4063 (MCPS-088) — responder-SIGNATURE acceptance, run through the
    // SAME production verifier the `online_ocsp` build ships ===================
    //
    // These prove the cryptographic gate END-TO-END through the production
    // `verify_and_map_response`: a response SIGNED by the issuer's key with the
    // correct CertID/freshness/nonce is ADMITTED; a forged/wrong-key or empty
    // signature is DENIED. The verifier (x509-parser/ring) is part of the
    // `online_ocsp` module, so these tests exercise the production path, not a
    // parallel flavor. The in-tree, Bazel-addressable test signer is Ed25519
    // (ed25519-dalek); the verifier is algorithm-agnostic and ALSO covers RSA
    // PKCS#1 SHA-256/384/512 and ECDSA P-256/P-384 (exercised by the
    // openssl-responder `ocsp_e2e_test`).

    pub(in crate::ocsp) fn ed25519_key(signer: &SigningKey) -> KeyPair {
        let pkcs8 = signer.to_pkcs8_der().expect("pkcs8");
        KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
            &PKCS_ED25519,
        )
        .expect("rcgen import")
    }

    /// Mint an Ed25519 issuer cert whose private key is `signer` (so the test
    /// can sign an OCSP response with the SAME key the issuer SPKI carries).
    /// Returns the issuer DER.
    fn mint_issuer_with_key(signer: &SigningKey) -> Vec<u8> {
        let key = ed25519_key(signer);
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-ed25519-ca");
        let cert = params.self_signed(&key).expect("issuer self-signed");
        cert.der().as_ref().to_vec()
    }

    /// What the response says beyond a single verdict, so each test isolates one gate.
    #[derive(Default)]
    pub(in crate::ocsp) struct Shape {
        /// `None` ⇒ the signing certificate's own subject (byName).
        pub(in crate::ocsp) responder_id: Option<ResponderId>,
        /// `Some(bytes)` ⇒ echo this nonce in the response extensions.
        pub(in crate::ocsp) echoed_nonce: Option<Vec<u8>>,
        /// Further verdicts for the SAME CertID, after the first.
        pub(in crate::ocsp) more_verdicts: Vec<CertStatus>,
        /// Certificates carried in `basic.certs` (a delegated responder).
        pub(in crate::ocsp) certs: Option<Vec<Certificate>>,
        /// Flip a signature byte to model a forgery.
        pub(in crate::ocsp) corrupt: bool,
    }

    /// The key that signs a response and the certificate whose subject names it.
    pub(in crate::ocsp) struct Signing<'a> {
        pub(in crate::ocsp) key: &'a SigningKey,
        pub(in crate::ocsp) cert_der: &'a [u8],
    }

    /// Build a response for `target` with `status`, then sign its `tbs_response_data`
    /// with `signing`. The response names the signing certificate's subject as its
    /// responder unless `shape` names another. Returns the response DER.
    pub(in crate::ocsp) fn signed_response_with(
        signing: &Signing<'_>,
        target: &Target<'_>,
        status: CertStatus,
        shape: Shape,
    ) -> Vec<u8> {
        let issuer = Certificate::from_der(target.issuer_der).expect("issuer");
        let signer_cert = Certificate::from_der(signing.cert_der).expect("signer");
        let requested =
            crate::ocsp::SentRequest::with_nonce(target.leaf_der, target.issuer_der, Vec::new())
                .expect("sent request");
        let responses = std::iter::once(status)
            .chain(shape.more_verdicts)
            .map(|status| {
                let mut single = SingleResponse::new(
                    requested.cert_id().clone(),
                    status,
                    gtime(Ymd(2024, 1, 1)),
                );
                single.next_update = Some(gtime(Ymd(2024, 1, 2)));
                single
            })
            .collect();
        let tbs = ResponseData {
            version: Version::V1,
            responder_id: shape.responder_id.unwrap_or_else(|| {
                ResponderId::ByName(signer_cert.tbs_certificate.subject.clone())
            }),
            produced_at: gtime(Ymd(2024, 1, 1)),
            responses,
            response_extensions: echoed_nonce_extensions(shape.echoed_nonce, &issuer),
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let mut bits = signing.key.sign(&tbs_der).to_bytes().to_vec();
        if shape.corrupt {
            bits[0] ^= 0xFF;
        }
        successful_response_der(
            tbs,
            Signature {
                // id-Ed25519 (RFC 8410), the OID x509-parser maps to ED25519.
                alg_oid: "1.3.101.112",
                bits,
                certs: shape.certs,
            },
        )
    }

    /// An Ed25519 issuer, the leaf it is asked about, and the issuer's signing key.
    struct Setup {
        signer: SigningKey,
        issuer_der: Vec<u8>,
        leaf_der: Vec<u8>,
    }

    /// A fresh Ed25519 issuer with the leaf it is asked about.
    fn ed25519_setup() -> Setup {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let issuer_der = mint_issuer_with_key(&signer);
        Setup {
            signer,
            issuer_der,
            leaf_der: mint_leaf_with_aia("http://ocsp.example.test/r"),
        }
    }

    /// The target `setup`'s responses answer.
    fn target_of(setup: &Setup) -> Target<'_> {
        Target {
            issuer_der: &setup.issuer_der,
            leaf_der: &setup.leaf_der,
        }
    }

    /// A response signed by the issuer key itself, answering `setup`'s leaf.
    fn respond(setup: &Setup, status: CertStatus, shape: Shape) -> Vec<u8> {
        signed_response_with(
            &Signing {
                key: &setup.signer,
                cert_der: &setup.issuer_der,
            },
            &target_of(setup),
            status,
            shape,
        )
    }

    /// Verify `response` as the answer to a request for `setup`'s leaf.
    fn verify_for(
        setup: &Setup,
        response: &[u8],
        nonce: &[u8],
        now: SystemTime,
    ) -> Result<TrustedRevocationAnswer, OcspError> {
        verify_and_map_response(response, &target_of(setup).sent(nonce), now)
    }

    #[test]
    fn signed_good_is_admitted() {
        let setup = ed25519_setup();
        let response = respond(&setup, CertStatus::good(), Shape::default());
        let answer = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)))
            .expect("a correctly-signed, fresh, bound Good must verify");
        assert_eq!(
            answer.status(),
            CertRevocationStatus::Good,
            "a verified Good admits the connection"
        );
        let checker = OcspChecker::new(None);
        let evidence = || RevocationEvidence::Answered(answer.clone());
        assert!(checker.allows(evidence(), at(Ymd(2024, 1, 1))));
        assert!(
            !checker.allows(evidence(), at(Ymd(2025, 1, 1))),
            "the same answer is not an admission token a year later"
        );
    }

    /// The end-to-end negative control for the `revoked` CHOICE: a response
    /// that clears every trust gate (real signature, matching responder id,
    /// bound CertID, fresh) and carries `revoked` must map to `Revoked` and
    /// be refused by the policy.
    #[test]
    fn signed_revoked_is_mapped_revoked_and_refused() {
        let setup = ed25519_setup();
        let response = respond(&setup, revoked_status(), Shape::default());
        let answer = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)))
            .expect("a correctly-signed, fresh, bound response must verify");
        assert_eq!(
            answer.status(),
            CertRevocationStatus::Revoked,
            "a verified revoked wire status must reach the policy as Revoked"
        );
        assert!(
            !OcspChecker::new(None)
                .allows(RevocationEvidence::Answered(answer), at(Ymd(2024, 1, 1))),
            "revoked denies"
        );
    }

    #[test]
    fn forged_signature_is_denied() {
        let setup = ed25519_setup();
        let response = respond(
            &setup,
            CertStatus::good(),
            Shape {
                corrupt: true,
                ..Shape::default()
            },
        );
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::SignatureNotVerified(_))),
            "a forged signature must be rejected, got {result:?}"
        );
    }

    #[test]
    fn wrong_key_signature_is_denied() {
        // Signed by a DIFFERENT key than the issuer SPKI → no candidate
        // verifies → denied.
        let setup = ed25519_setup();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let response = signed_response_with(
            &Signing {
                key: &attacker,
                cert_der: &setup.issuer_der,
            },
            &target_of(&setup),
            CertStatus::good(),
            Shape::default(),
        );
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::SignatureNotVerified(_))),
            "a response signed by a non-issuer key must be rejected, got {result:?}"
        );
    }

    #[test]
    fn signed_good_for_wrong_certid_is_denied() {
        // Correctly SIGNED, but the SingleResponse answers a DIFFERENT cert: sign a
        // response that BINDS to `other_leaf`, but we query for `setup.leaf_der`.
        let setup = ed25519_setup();
        let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
        let response = signed_response_with(
            &Signing {
                key: &setup.signer,
                cert_der: &setup.issuer_der,
            },
            &Target {
                issuer_der: &setup.issuer_der,
                leaf_der: &other_leaf,
            },
            CertStatus::good(),
            Shape::default(),
        );
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::CertIdMismatch)),
            "a signed Good for a different CertID must be rejected, got {result:?}"
        );
    }

    /// Two verdicts for the requested certificate would resolve to whichever came first;
    /// a correctly signed, fresh response carrying `good` then `revoked` is refused.
    #[test]
    fn signed_response_answering_our_certid_twice_is_denied() {
        let setup = ed25519_setup();
        let response = respond(
            &setup,
            CertStatus::good(),
            Shape {
                more_verdicts: vec![revoked_status()],
                ..Shape::default()
            },
        );
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::CertIdMismatch)),
            "an ambiguous answer must fail closed, got {result:?}"
        );
    }

    /// The responder-identity gate in isolation: the response is signed by the issuer key,
    /// so the signature gate passes, but it names another responder.
    #[test]
    fn signed_good_with_a_foreign_responder_id_is_denied() {
        let setup = ed25519_setup();
        let response = respond(
            &setup,
            CertStatus::good(),
            Shape {
                responder_id: Some(ResponderId::ByName(
                    "CN=some-other-responder".parse().expect("name"),
                )),
                ..Shape::default()
            },
        );
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2024, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::ResponderIdentityMismatch(_))),
            "a response naming a responder it did not sign as must be denied, got {result:?}"
        );
    }

    /// The nonce gate in isolation: a correctly signed response echoing nonce A under a
    /// request that carried nonce B is a replay; the same response under A is admitted.
    #[test]
    fn signed_good_echoing_another_nonce_is_denied() {
        let setup = ed25519_setup();
        let response = respond(
            &setup,
            CertStatus::good(),
            Shape {
                echoed_nonce: Some(b"nonce-A-aaaaaaaa".to_vec()),
                ..Shape::default()
            },
        );
        let replayed = verify_for(&setup, &response, b"nonce-B-bbbbbbbb", at(Ymd(2024, 1, 1)));
        assert!(
            matches!(replayed, Err(OcspError::NonceMismatch)),
            "a response echoing another request's nonce must be denied, got {replayed:?}"
        );
        verify_for(&setup, &response, b"nonce-A-aaaaaaaa", at(Ymd(2024, 1, 1)))
            .expect("the positive control: the same response under its own nonce is admitted");
    }

    #[test]
    fn signed_good_but_stale_is_denied() {
        let setup = ed25519_setup();
        let response = respond(&setup, CertStatus::good(), Shape::default());
        // now is far past nextUpdate (Jan 2) → stale.
        let result = verify_for(&setup, &response, REQUEST_NONCE, at(Ymd(2025, 1, 1)));
        assert!(
            matches!(result, Err(OcspError::NotFresh(_))),
            "a signed but stale Good must be rejected, got {result:?}"
        );
    }
}
