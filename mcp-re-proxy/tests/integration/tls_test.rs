//! MCPS-025 — RustlsDirectProvider: identity extraction + mTLS round-trip
//! (ADR-MCPS-014).
//!
//! Certificates are minted in-process with `rcgen` (no committed private-key
//! fixtures). Two layers of test:
//!   1. `extract_identity` priority (URI SAN → DNS SAN → CN) over real DER.
//!   2. A full blocking TLS round-trip: the server terminates TLS, requires +
//!      verifies a client certificate, extracts its identity, and serves one
//!      request; a missing or untrusted client certificate fails closed.

mod pki;
mod serving;
mod signers;

use std::sync::Arc;

use mcp_re_proxy::extract_identity;
use mcp_re_proxy::transport::IdentityPolicy;
use mcp_re_proxy::transport::IdentitySource;

use rcgen::SanType;

use pki::dns;
use pki::make_ca;
use pki::make_client_leaf_valid_between;
use pki::make_client_leaf_with_serial;
use pki::make_crl;
use pki::make_crl_full;
use pki::make_leaf;
use pki::uri;
use pki::Validity;
use serving::agent_credential;
use serving::delegated_config;
use serving::dial;
use serving::expect_jsonrpc_answer_ok;
use serving::server_config_for;
use serving::server_config_trusting;
use serving::spawn_ok_server;
use serving::spawn_server;
use serving::AGENT_1;
use serving::JSONRPC_BODY;
use serving::OK_BODY;
use signers::make_ecdsa_server_leaf;
use signers::make_ed25519_server_leaf;
use signers::CorruptingEd25519Tls;
use signers::LocalEd25519Tls;

// ---------------------------------------------------------------------------
// 1. Policy-selected identity extraction (NO implicit fallback).
// ---------------------------------------------------------------------------

#[test]
fn uri_san_policy_reads_the_uri_san() {
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            dns("agent.example.org"),
            uri("spiffe://example.org/agent-1"),
        ],
        Some("ignored-cn"),
        true,
    );
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(id.value(), "spiffe://example.org/agent-1");
    assert_eq!(id.source(), IdentitySource::UriSan);
}

#[test]
fn dns_san_policy_reads_the_dns_san() {
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            dns("agent.example.org"),
            uri("spiffe://example.org/agent-1"),
        ],
        Some("ignored"),
        true,
    );
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
    assert_eq!(id.value(), "agent.example.org");
    assert_eq!(id.source(), IdentitySource::DnsSan);
}

#[test]
fn selected_source_absent_fails_closed_no_fallback() {
    let ca = make_ca();
    // A cert with ONLY a DNS SAN + CN, no URI SAN.
    let (leaf, _key) = make_leaf(&ca, vec![dns("agent.example.org")], Some("agent-cn"), true);
    // URI-SAN policy must NOT fall through to the DNS SAN or the CN.
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "URI-SAN policy must fail closed when no URI SAN is present"
    );
    // A cert with ONLY a URI SAN: DNS-SAN policy must not fall through to it.
    let (leaf2, _key2) = make_leaf(&ca, vec![uri("spiffe://example.org/a")], None, true);
    assert!(
        extract_identity(leaf2.as_ref(), IdentityPolicy::DnsSan).is_none(),
        "DNS-SAN policy must fail closed when no DNS SAN is present"
    );
}

// ---------------------------------------------------------------------------
// 1b. MCPS-078 (audit gap G-5): adversarial extract_identity — hostile-but-valid
//     SAN bytes, multiple SANs (deterministic selection), and empty SAN lists.
//     All assertions are black-box on the public `extract_identity`.
// ---------------------------------------------------------------------------

#[test]
fn multiple_uri_sans_select_first_deterministically() {
    // Two URI SANs. `extract_identity` (UriSan) is `find_map` over the cert's
    // general_names IN ORDER, so the FIRST URI SAN wins. Mint once, extract
    // repeatedly: the selection is stable (same cert → same identity).
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![
            uri("spiffe://example.org/agent-FIRST"),
            uri("spiffe://example.org/agent-SECOND"),
        ],
        None,
        true,
    );
    let first = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(
        first.value(),
        "spiffe://example.org/agent-FIRST",
        "the FIRST URI SAN (find_map order) must win"
    );
    assert_eq!(first.source(), IdentitySource::UriSan);
    // Determinism: repeated extraction over the SAME cert yields the SAME value.
    for _ in 0..8 {
        let again = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
        assert_eq!(
            again.value(),
            first.value(),
            "selection must be deterministic"
        );
        assert_eq!(again.source(), first.source());
    }
}

#[test]
fn multiple_dns_sans_select_first_deterministically() {
    // Analogous multi-DNS-SAN case for the DnsSan policy: FIRST DNS SAN wins,
    // deterministically.
    let ca = make_ca();
    let (leaf, _key) = make_leaf(
        &ca,
        vec![dns("first.example.org"), dns("second.example.org")],
        None,
        true,
    );
    let first = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
    assert_eq!(
        first.value(),
        "first.example.org",
        "the FIRST DNS SAN (find_map order) must win"
    );
    assert_eq!(first.source(), IdentitySource::DnsSan);
    for _ in 0..8 {
        let again = extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).expect("identity");
        assert_eq!(
            again.value(),
            first.value(),
            "selection must be deterministic"
        );
    }
}

#[test]
fn uri_san_with_nul_control_char_fails_closed() {
    // A NUL (0x00) and other C0 control chars are valid IA5 (ASCII 0x00-0x7F), so
    // `SanType::URI`'s `try_into` ACCEPTS them and the cert mints. C096: the value
    // then reaches the transport binding and the logs, so it is held to the same
    // strict rules as an asserted trusted-ingress identity — a control character is
    // a rejection, not a value.
    let ca = make_ca();
    let hostile = "spiffe://example.org/agent\u{0000}injected";
    // Confirm the byte is IA5-representable (the premise of this test).
    let san: SanType = SanType::URI(hostile.try_into().expect("NUL/C0 is valid IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "a URI SAN carrying a control character must fail closed"
    );
    // The original anti-truncation requirement still holds, and holds STRICTLY
    // better: the outcome is no identity at all, so there is no way for the prefix
    // before the NUL to be mistaken for the verified identity.
}

#[test]
fn crlf_in_dns_san_fails_closed_like_the_header_path() {
    // The log-injection/smuggling shape the header path already rejects, asserted for the
    // DNS SAN policy so the fix is not URI-SAN-specific.
    let ca = make_ca();
    let smuggle = "host.example.org\r\nX-Spoof: evil";
    let san: SanType = SanType::DnsName(smuggle.try_into().expect("CRLF is valid IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).is_none(),
        "a DNS SAN carrying CRLF must fail closed"
    );
}

#[test]
fn oversized_uri_san_fails_closed_at_the_same_bound_as_the_header_path() {
    // Length is bounded by MAX_PEER_IDENTITY_LEN for BOTH identity provenances:
    // an issuer-minted SAN is no more trustworthy as to size than a forwarded
    // header. At the bound it is admitted; one byte over, it is not.
    let ca = make_ca();
    let prefix = "spiffe://example.org/";
    let pad = mcp_re_proxy::communication_assurance::MAX_PEER_IDENTITY_LEN - prefix.len();

    let at_bound = format!("{prefix}{}", "a".repeat(pad));
    assert_eq!(
        at_bound.len(),
        mcp_re_proxy::communication_assurance::MAX_PEER_IDENTITY_LEN
    );
    let san: SanType = SanType::URI(at_bound.as_str().try_into().expect("ascii is IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan)
        .expect("a value AT the bound must be admitted");
    assert_eq!(id.value(), at_bound);

    let over = format!("{prefix}{}", "a".repeat(pad + 1));
    let san: SanType = SanType::URI(over.as_str().try_into().expect("ascii is IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "one byte over the bound must fail closed"
    );
}

#[test]
fn padded_uri_san_is_trimmed_to_the_same_value_as_the_header_path() {
    // Canonicalization parity: the header path trims before comparing, so the cert
    // path must too — otherwise " spiffe://…/agent-1 " and "spiffe://…/agent-1" are
    // two different identities depending on which transport terminated mTLS, and one
    // signer mapping cannot admit both (the same class of split the
    // `identity_parity_tests` module exists to prevent).
    let ca = make_ca();
    let padded = "  spiffe://example.org/agent-1  ";
    let san: SanType = SanType::URI(padded.try_into().expect("ascii is IA5"));
    let (leaf, _key) = make_leaf(&ca, vec![san], None, true);
    let id = extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).expect("identity");
    assert_eq!(
        id.value(),
        "spiffe://example.org/agent-1",
        "the extracted identity must be the trimmed value"
    );
}

#[test]
fn non_ia5_unicode_uri_san_is_rejected_at_mint_time() {
    // Unicode beyond ASCII is NOT IA5-representable, so `SanType::URI`'s `try_into`
    // REJECTS it: minting fails with an error rather than producing a surprising
    // identity. We assert the error path on the `try_into` directly (per the issue,
    // do not force a degenerate cert).
    let non_ia5 = "spiffe://example.org/agent-\u{00e9}"; // 'é' (U+00E9) > 0x7F
                                                         // The IA5 string type itself is not nameable (rcgen keeps it crate-private and
                                                         // exposes it only through `SanType`), so the conversion is driven through the
                                                         // `SanType::URI` constructor that mint sites actually use.
    let result = non_ia5.try_into().map(SanType::URI);
    assert!(
        result.is_err(),
        "a non-IA5 (non-ASCII unicode) URI SAN value must be rejected by try_into, \
         not silently coerced"
    );
}

#[test]
fn no_san_fails_closed_for_every_san_policy() {
    // Empty SAN list: both policies fail closed (None), and the present Common Name is
    // never read in their place.
    let ca = make_ca();
    let (leaf, _key) = make_leaf(&ca, vec![], Some("legacy-cn"), true);
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::UriSan).is_none(),
        "UriSan must fail closed with no SAN"
    );
    assert!(
        extract_identity(leaf.as_ref(), IdentityPolicy::DnsSan).is_none(),
        "DnsSan must fail closed with no SAN"
    );
}

// ---------------------------------------------------------------------------
// 2. mTLS round-trip.
// ---------------------------------------------------------------------------

#[test]
fn mtls_round_trip_extracts_client_identity_and_serves_request() {
    let client_ca = make_ca();
    let (config, server_root) = server_config_for(&client_ca);
    let (addr, server) = spawn_server(config, expect_jsonrpc_answer_ok);

    let response = dial(
        addr,
        &server_root,
        Some(agent_credential(&client_ca)),
        JSONRPC_BODY,
    )
    .expect("client round trip");
    assert_eq!(response, OK_BODY);

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(identity.identity().as_str(), AGENT_1);
    assert_eq!(
        identity.identity_source(),
        mcp_re_proxy::communication_assurance::CertificateIdentitySource::UriSan
    );
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G: delegated TLS handshake signing. The server's TLS key is NOT
// exported to rustls; instead a `RawEd25519TlsSigner` (here a local Ed25519 key
// standing in for a PKCS#11 token / KMS) signs each handshake. A real rustls
// client completing the mTLS handshake PROVES the delegated Ed25519 signature is
// wire-correct (rustls verifies it against the server's Ed25519 certificate).
// ---------------------------------------------------------------------------

#[test]
fn delegated_ed25519_tls_handshake_round_trip() {
    let client_ca = make_ca();
    // Server CA issues the (Ed25519) server leaf; the proxy trusts `client_ca` for
    // CLIENT auth. The server's TLS private key never reaches rustls — the resolver
    // holds only the public cert + the delegated signer.
    let server_ca = make_ca();
    let (server_cert, delegated_signer) = make_ed25519_server_leaf(&server_ca);
    // Through the OWNER's path, not around it. `build_delegated_config` validates the
    // credential (ADR-MCPRE-063 Slice 3: the certificate and the delegated signer must
    // present the same public key) AND binds the resolver to this listener's own signing
    // budget — the fourth of the four things THM-0048 says are established together.
    let config = delegated_config(&client_ca, server_cert, delegated_signer)
        .expect("delegated server config");
    let (addr, server) = spawn_server(Arc::new(config), expect_jsonrpc_answer_ok);

    // Use a client that FULLY validates the server (chain to the test CA, hostname,
    // AND CertificateVerify signature): the handshake completes only if the delegated
    // signer produced a cryptographically valid Ed25519 CertificateVerify over the
    // transcript. Nothing is asserted/bypassed, so this proves delegated-signing
    // correctness end to end.
    let response = dial(
        addr,
        &server_ca.der(),
        Some(agent_credential(&client_ca)),
        JSONRPC_BODY,
    )
    .expect("client round trip over a delegated-signed handshake");
    assert_eq!(response, OK_BODY);

    let identity = server.join().expect("join").expect("serve ok");
    assert_eq!(
        identity
            .expect("verified client identity")
            .identity()
            .as_str(),
        AGENT_1
    );
}

// ---------------------------------------------------------------------------
// ADR-MCPS-028 §G / issue #58: the VALIDATED delegated build path. It wraps the
// frozen `build_server_config_delegated_with_crls` with two fail-closed checks at
// CONFIG CONSTRUCTION (before any server starts): Ed25519-only leaf, and the
// signer's public key must match the leaf certificate's public key.
// ---------------------------------------------------------------------------

#[test]
fn validated_delegated_build_round_trip_and_corrupted_sig_fails() {
    // (b) The validated builder accepts a signer whose pubkey MATCHES the leaf cert,
    // and a real full-WebPKI client completes the mTLS handshake — proving the
    // delegated Ed25519 signature is wire-correct. Then a CORRUPTED signature breaks
    // the handshake (load-bearing).
    let client_ca = make_ca();
    let server_ca = make_ca();
    let (server_cert, delegated_signer) = make_ed25519_server_leaf(&server_ca);
    let config = delegated_config(&client_ca, server_cert, delegated_signer)
        .expect("validated delegated server config (matching key) must build");
    let (addr, server) = spawn_server(Arc::new(config), expect_jsonrpc_answer_ok);

    let response = dial(
        addr,
        &server_ca.der(),
        Some(agent_credential(&client_ca)),
        JSONRPC_BODY,
    )
    .expect("client round trip over the validated delegated handshake");
    assert_eq!(response, OK_BODY);
    let _ = server.join().expect("join").expect("serve ok");

    // Corrupting the delegated signature must break the handshake (the validating
    // client verifies CertificateVerify). A signer that flips a bit of every raw
    // signature drives this.
    let client_ca2 = make_ca();
    let server_ca2 = make_ca();
    let (server_cert2, honest_signer) = make_ed25519_server_leaf(&server_ca2);
    let corrupting = CorruptingEd25519Tls(honest_signer);
    let config2 = delegated_config(&client_ca2, server_cert2, corrupting)
        .expect("build still succeeds: the public key matches; the BREAK is the bad signature");
    let (addr2, server2) = spawn_ok_server(Arc::new(config2));
    let result = dial(
        addr2,
        &server_ca2.der(),
        Some(agent_credential(&client_ca2)),
        JSONRPC_BODY,
    );
    assert!(
        result.is_err(),
        "a corrupted delegated signature MUST fail the validating handshake"
    );
    let _ = server2.join();
}

#[test]
fn validated_delegated_build_rejects_cert_signer_key_mismatch() {
    // (c) The signer signs for a DIFFERENT key than the leaf certificate presents.
    // The validated builder must FAIL CLOSED at construction — no server.
    let client_ca = make_ca();
    let server_ca = make_ca();
    let (server_cert, _matching_signer) = make_ed25519_server_leaf(&server_ca);
    // A signer with an unrelated key (seed 0xAA..) — its pubkey cannot equal the
    // leaf's.
    let mismatched = LocalEd25519Tls::from_repeated_seed_byte(0xAA);

    let err = delegated_config(&client_ca, server_cert, mismatched)
        .expect_err("a cert↔signer key mismatch must fail closed at config construction");
    assert!(
        matches!(err, mcp_re_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch, got {err:?}"
    );
}

#[test]
fn validated_delegated_build_rejects_non_ed25519_leaf() {
    // (d) A non-Ed25519 (ECDSA P-256) leaf under delegated mode must FAIL CLOSED:
    // delegated TLS is Ed25519-only. The signer's own key is irrelevant — the leaf
    // SPKI is rejected first.
    let client_ca = make_ca();
    let server_ca = make_ca();
    let ecdsa_leaf = make_ecdsa_server_leaf(&server_ca);
    let signer = LocalEd25519Tls::from_repeated_seed_byte(3);

    let err = delegated_config(&client_ca, ecdsa_leaf, signer)
        .expect_err("a non-Ed25519 leaf must fail closed under delegated mode");
    assert!(
        matches!(err, mcp_re_proxy::TlsError::DelegatedKeyMismatch(_)),
        "expected DelegatedKeyMismatch (Ed25519-only), got {err:?}"
    );
}

#[test]
fn missing_client_certificate_is_rejected() {
    let client_ca = make_ca();
    let (config, server_root) = server_config_for(&client_ca);
    let (addr, server) = spawn_ok_server(config);

    // Client presents NO certificate; the server requires one → fail closed.
    let _ = dial(addr, &server_root, None, b"{}");
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "server must reject a connection with no client certificate"
    );
}

#[test]
fn untrusted_client_certificate_is_rejected() {
    let client_ca = make_ca();
    let (config, server_root) = server_config_for(&client_ca);

    // A client cert signed by a DIFFERENT CA than the server's client-CA root.
    let rogue_ca = make_ca();
    let (rogue_cert, rogue_key) =
        make_leaf(&rogue_ca, vec![uri("spiffe://evil/agent")], None, true);
    let (addr, server) = spawn_ok_server(config);

    let _ = dial(
        addr,
        &server_root,
        Some((vec![rogue_cert], rogue_key)),
        b"{}",
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "server must reject a client certificate not signed by the configured client-CA"
    );
}

// ---------------------------------------------------------------------------
// 3. Max client-certificate lifetime enforcement (v1 revocation posture).
// ---------------------------------------------------------------------------

fn error_body(bytes: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"].as_str().unwrap_or("").to_string()
}

#[test]
fn over_long_client_cert_is_rejected() {
    let client_ca = make_ca();
    let (config, server_root) = server_config_for(&client_ca);
    // Currently-valid but long-lived (2020..2035 ≈ 15y) cert.
    let credential = make_client_leaf_valid_between(
        &client_ca,
        vec![uri(AGENT_1)],
        &Validity {
            not_before: (2020, 1, 1),
            not_after: (2035, 1, 1),
        },
    );
    let (addr, server) = spawn_server(config, |_req, _id| {
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".to_vec()
    });
    let body = dial(
        addr,
        &server_root,
        Some((vec![credential.0], credential.1)),
        b"{\"jsonrpc\":\"2.0\",\"id\":1}",
    )
    .expect("handshake succeeds; app-level rejection");
    let _ = server.join();
    assert_eq!(
        error_body(&body),
        "mcp-re.transport_binding_failed",
        "a client cert exceeding the max lifetime must be rejected"
    );
}

#[test]
fn within_limit_client_cert_is_served() {
    let client_ca = make_ca();
    let (config, server_root) = server_config_for(&client_ca);
    // A now-relative 1860s cert, well inside the 1h ceiling → served.
    let (addr, server) = spawn_ok_server(config);
    let body = dial(
        addr,
        &server_root,
        Some(agent_credential(&client_ca)),
        b"{\"jsonrpc\":\"2.0\",\"id\":1}",
    )
    .expect("round trip");
    let _ = server.join();
    assert_eq!(body, OK_BODY, "a cert within the max lifetime is served");
}

// ---------------------------------------------------------------------------
// 4. #3839 — offline CRL client-certificate revocation (OFFLINE only; no online
//    OCSP / CRL-distribution-point fetching, which is deferred to a follow-up).
//
//    Both tests mint a CA, issue a client cert with an explicit serial, build a
//    CRL signed by that CA, and configure the proxy's verifier with it:
//      (a) a NON-revoked client cert from the same CA still completes the mTLS
//          round-trip;
//      (b) the REVOKED client cert's handshake is REJECTED (fail closed).
// ---------------------------------------------------------------------------

#[test]
fn non_revoked_client_cert_completes_handshake_with_crl_configured() {
    let client_ca = make_ca();
    // The CRL revokes serial 0xBADBAD; this client uses a DIFFERENT serial.
    let crl = make_crl(&client_ca, &[0x00BA_DBAD]);
    let (config, server_root) = server_config_trusting(&[&client_ca], vec![crl]);
    let credential =
        make_client_leaf_with_serial(&client_ca, "spiffe://example.org/agent-good", 0x0000_0042);

    let (addr, server) = spawn_server(config, expect_jsonrpc_answer_ok);
    let response = dial(
        addr,
        &server_root,
        Some((vec![credential.0], credential.1)),
        JSONRPC_BODY,
    )
    .expect("non-revoked client round trip");
    assert_eq!(
        response, OK_BODY,
        "a non-revoked client cert from the same CA must still complete the mTLS round-trip"
    );
    server.join().expect("join").expect("serve ok");
}

#[test]
fn revoked_client_cert_handshake_is_rejected() {
    let client_ca = make_ca();
    let revoked_serial = 0x0000_0099;
    // The client cert and the CRL share the SAME serial → this cert is revoked.
    let credential = make_client_leaf_with_serial(
        &client_ca,
        "spiffe://example.org/agent-revoked",
        revoked_serial,
    );
    let crl = make_crl(&client_ca, &[revoked_serial]);
    let (config, server_root) = server_config_trusting(&[&client_ca], vec![crl]);
    let (addr, server) = spawn_ok_server(config);

    // The handshake must fail closed: a revoked client cert is rejected by the
    // verifier, so serve_once surfaces an error (the inner is never reached).
    let _ = dial(
        addr,
        &server_root,
        Some((vec![credential.0], credential.1)),
        JSONRPC_BODY,
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "the server must reject a client certificate revoked by the configured CRL"
    );
}

// ADR-MCPS-023 §A1 (v0.9, MCPS-58), conformance vector (b): a client CRL past its
// `nextUpdate` is STALE. With expiration now enforced
// (`enforce_revocation_expiration`), a stale CRL is unusable and the verifier fails
// closed — even for a cert the CRL does NOT revoke. Under the previous
// `ExpirationPolicy::Ignore` default this same handshake would have SUCCEEDED, so
// this test pins the behavior change.
#[test]
fn stale_crl_fails_client_handshake_closed() {
    let client_ca = make_ca();
    // A non-revoked client (serial 0x42; the CRL lists a different serial).
    let credential =
        make_client_leaf_with_serial(&client_ca, "spiffe://example.org/agent-good", 0x0000_0042);
    // Stale: thisUpdate 2020-01-01, nextUpdate 2020-06-01 — long in the past.
    let stale_crl = make_crl_full(&client_ca, &[0x00BA_DBAD], (2020, 1, 1), (2020, 6, 1));
    let (config, server_root) = server_config_trusting(&[&client_ca], vec![stale_crl]);
    let (addr, server) = spawn_ok_server(config);

    let _ = dial(
        addr,
        &server_root,
        Some((vec![credential.0], credential.1)),
        JSONRPC_BODY,
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "a stale CRL (past nextUpdate) must fail the handshake closed with expiration enforced, \
         even for a cert the CRL does not revoke"
    );
}

/// A chain the configured CRLs do not COVER: revocation status is unknown, and unknown is
/// denied (ADR-MCPRE-059 THM-0054).
///
/// The gap the three tests above leave. A revoked cert is denied because a CRL says so, and a
/// stale CRL is denied because expiration is enforced — both are cases where revocation
/// checking ran and produced an answer. This is the case where it CANNOT: two client CAs are
/// trusted, a CRL is supplied for the first only, and the client presents a leaf issued by
/// the second. Nothing about that leaf is known to be bad; nothing is known to be good
/// either, and `UnknownStatusPolicy::Deny` is what makes the difference between failing
/// closed and admitting a credential whose status could not be determined.
///
/// It is the same posture `ClientRevocationIndex::admits` holds per request, measured at the
/// handshake so the two cannot disagree.
#[test]
fn a_client_whose_revocation_status_cannot_be_determined_is_denied() {
    let covered_ca = make_ca();
    let uncovered_ca = make_ca();
    // A CRL for the FIRST CA only. It revokes nothing this test presents; its role is to
    // switch revocation checking ON, so the second CA's leaf reaches the unknown-status
    // decision rather than the no-CRLs-configured path where no check runs at all.
    let crl = make_crl(&covered_ca, &[0x00BA_DBAD]);
    let (config, server_root) = server_config_trusting(&[&covered_ca, &uncovered_ca], vec![crl]);

    // The client is issued by the CA no CRL covers, and is not revoked by anything.
    let credential = make_client_leaf_with_serial(
        &uncovered_ca,
        "spiffe://example.org/agent-uncovered",
        0x0000_0077,
    );
    let (addr, server) = spawn_ok_server(config);

    let _ = dial(
        addr,
        &server_root,
        Some((vec![credential.0], credential.1)),
        JSONRPC_BODY,
    );
    let result = server.join().expect("join");
    assert!(
        result.is_err(),
        "a client certificate whose revocation status the configured CRLs cannot determine \
         must be denied. Admitting it is revocation checking failing OPEN: the credential \
         is not known to be good, and the deployment cannot tell whether it was withdrawn."
    );
}

// ADR-MCPS-023 §A1 (MCPS-58): the pure startup freshness gate. Boundaries are
// derived from the minted CRL's own nextUpdate so the test is independent of the
// absolute date.
#[test]
fn crl_freshness_classifies_fresh_near_and_stale() {
    use mcp_re_proxy::client_crl_publication::{crl_freshness, CrlFreshness};
    let ca = make_ca();
    let crl = make_crl_full(&ca, &[0x01], (2020, 1, 1), (2020, 6, 1));
    let warn = 6 * 3600;

    // Recover nextUpdate from a Stale classification at a far-future instant.
    let nu = match crl_freshness(crl.as_ref(), i64::MAX / 2, warn).expect("parse") {
        CrlFreshness::Stale { next_update_unix } => next_update_unix,
        other => panic!("expected Stale at +inf, got {other:?}"),
    };

    assert_eq!(
        crl_freshness(crl.as_ref(), nu - warn - 1, warn).expect("parse"),
        CrlFreshness::Fresh,
        "before the warn window the CRL is Fresh"
    );
    assert_eq!(
        crl_freshness(crl.as_ref(), nu - 1, warn).expect("parse"),
        CrlFreshness::NearExpiry {
            next_update_unix: nu
        },
        "inside the warn window but before nextUpdate the CRL is NearExpiry"
    );
    assert_eq!(
        crl_freshness(crl.as_ref(), nu, warn).expect("parse"),
        CrlFreshness::Stale {
            next_update_unix: nu
        },
        "at exactly nextUpdate the CRL is Stale (boundary is inclusive)"
    );
}

// ADR-MCPS-023 §A1 (MCPS-58): a malformed CRL is a hard error — the gate fails
// closed rather than silently skipping (the verifier build would reject it too).
#[test]
fn crl_freshness_rejects_malformed_der() {
    use mcp_re_proxy::client_crl_publication::crl_freshness;
    assert!(
        crl_freshness(b"not a der crl", 0, 3600).is_err(),
        "a malformed CRL must be a hard error, not a silent pass"
    );
}

// ADR-MCPS-023 §A1 (MCPS-58): the posture facts feeding the
// `mcp-re.revocation.posture ... revocation_mode=static_crl_snapshot` diagnostic
// line — a canonical `sha256:` digest and the CRL's this/next update timestamps.
#[test]
fn crl_posture_reports_canonical_digest_and_dates() {
    use mcp_re_proxy::client_crl_publication::crl_posture;
    let ca = make_ca();
    let crl = make_crl_full(&ca, &[0x01], (2024, 1, 1), (2999, 1, 1));
    let p = crl_posture(crl.as_ref()).expect("parse");
    assert!(
        p.crl_digest.starts_with("sha256:"),
        "crl_digest is the MCP-RE hash-identifier format, got {}",
        p.crl_digest
    );
    assert_eq!(
        p.crl_digest,
        mcp_re_core::sha256_hash_id(crl.as_ref()),
        "the digest is the SHA-256 of the CRL DER in canonical form"
    );
    let next = p.next_update_unix.expect("this CRL carries a nextUpdate");
    assert!(
        p.this_update_unix < next,
        "thisUpdate ({}) precedes nextUpdate ({next})",
        p.this_update_unix
    );
}
