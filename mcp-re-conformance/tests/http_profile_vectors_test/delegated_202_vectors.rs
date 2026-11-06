// SPDX-License-Identifier: Apache-2.0
//! Delegated bodyless-202 vectors (#424, owner ruling 2026-07-17).

use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::ActiveDelegatedKey;
use mcp_re_http_profile::custody::SigningWindow;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use super::delegation::issue_credential;
use super::delegation::server_signer;
use super::delegation::Grant;
use super::material::post;
use super::material::sign_as_client;
use super::material::SignatureInputEdit;
use super::material::CREATED;
use super::material::EXPIRES;
use super::schema::to_wire_request;
use super::schema::to_wire_response;
use super::schema::Delegated202Check;
use super::schema::Fixture;
use super::schema::Kind;
use super::schema::Vector;

const ROOT_KID: &str = "root-kid";
pub(super) const DELEGATED_KID: &str = "delegated-kid-1";
const AUDIENCE: &str = "verifier-1";
const AUDIENCE_HASH: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn root() -> SigningKey {
    SigningKey::from_seed_bytes(&[33u8; 32])
}

fn delegated() -> SigningKey {
    SigningKey::from_seed_bytes(&[55u8; 32])
}

fn credential() -> String {
    issue_credential(&Grant {
        issuer: &root(),
        issuer_kid: ROOT_KID,
        delegated: &delegated(),
        delegated_kid: DELEGATED_KID,
        jti: "evt-202",
        audience: AUDIENCE,
        audience_hash: AUDIENCE_HASH,
        epoch: EPOCH,
    })
}

fn notification() -> HttpRequest {
    let mut request = post(
        &[],
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    sign_as_client(&mut request, "vec-nonce-d202");
    request
}

fn check(response: &HttpResponse, note: &HttpRequest, revoked: bool) -> Delegated202Check {
    Delegated202Check {
        request: to_wire_request(note),
        response: to_wire_response(response),
        root_public_key_b64url: root().public_key().to_b64url(),
        root_kid: ROOT_KID.into(),
        verifier_audience: AUDIENCE.into(),
        audience_hash: AUDIENCE_HASH.into(),
        epoch: EPOCH.into(),
        revoked,
    }
}

fn fixture(name: &str, check: Delegated202Check, expected: &str) -> Fixture {
    Fixture {
        delegated_202_check: Some(check),
        ..Vector {
            name,
            kind: Kind::Delegated202,
            expected,
        }
        .blank()
    }
}

/// h47–h49: a delegated 202 verifying via the credential→root chain, the credential
/// stripped from the covered set, and a revoked delegated key.
pub(super) fn delegated_202_fixtures() -> Vec<Fixture> {
    let note = notification();
    let ack = sign_delegated_accepted_202(
        &note,
        &SigningWindow::stated(
            ActiveDelegatedKey::stated(
                delegated(),
                server_signer(DELEGATED_KID),
                credential(),
                DELEGATED_KID,
            ),
            CREATED,
            EXPIRES,
        ),
    )
    .expect("PEP delegated-signs the 202");

    // h48 — the credential header stripped from the COVERED set (still on the wire).
    //       An uncovered credential is unprotected — the load-bearing negative for
    //       the whole design.
    let mut uncovered = ack.clone();
    SignatureInputEdit::DropDelegationCredential.apply_to(&mut uncovered.headers);

    vec![
        // h47 — positive.
        fixture(
            "h47_delegated_202_valid",
            check(&ack, &note, false),
            "verify_ok",
        ),
        fixture(
            "h48_delegated_202_credential_uncovered",
            check(&uncovered, &note, false),
            "mcp-re.missing_envelope",
        ),
        // h49 — revoked delegated key: the revocation seam is live.
        fixture(
            "h49_delegated_202_revoked",
            check(&ack, &note, true),
            "mcp-re.delegation_revoked",
        ),
    ]
}
