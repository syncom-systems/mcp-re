// SPDX-License-Identifier: Apache-2.0
//! Running one fixture exactly as a third party would: from the frozen octets alone.

use mcp_re_core::b64url_decode;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::CoseVerificationKey;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ReceiptPositionProfile;
use mcp_re_http_profile::scitt::ResolvedTransparencyService;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::scitt::StatementLeafProfile;

use super::manifest::Fixture;
use super::material::ISSUER_KID;
use super::material::TS_KID;

/// Resolve `kid` to the Ed25519 key this corpus pins. The corpus is Ed25519 on both
/// sides; ES256 receipt verification is exercised by the unit tests, which can mint a
/// P-256 key pair without freezing one into the vectors.
fn resolve(kid: &str, expected: &str, key: VerificationKey) -> Option<CoseVerificationKey> {
    (kid == expected).then(|| key.into())
}

/// The wire code of the verdict a verifier reaches on `f`, or `verify_ok`.
pub(super) fn verdict(f: &Fixture) -> String {
    match decode(f) {
        Ok((statement, receipt)) => verify(f, &statement, &receipt),
        Err(refusal) => refusal,
    }
}

/// Parse both artifacts from their frozen octets; the wire code of a refusal to parse.
fn decode(f: &Fixture) -> Result<(SignedStatement, Receipt), String> {
    let refused = |e: mcp_re_http_profile::HttpProfileError| e.wire_code().to_owned();
    let statement = SignedStatement::from_cose(
        &b64url_decode(&f.statement_cose_b64url).expect("statement b64url"),
    )
    .map_err(refused)?;
    let receipt =
        Receipt::from_cose(&b64url_decode(&f.receipt_cose_b64url).expect("receipt b64url"))
            .map_err(refused)?;
    Ok((statement, receipt))
}

fn verify(f: &Fixture, statement: &SignedStatement, receipt: &Receipt) -> String {
    let issuer_key = VerificationKey::from_b64url(&f.issuer_pubkey_b64url).expect("issuer key");
    let ts_key = VerificationKey::from_b64url(&f.ts_pubkey_b64url).expect("ts key");
    match verify_receipt_offline(
        statement,
        receipt,
        |kid| resolve(kid, ISSUER_KID, issuer_key.clone()),
        |kid| {
            resolve(kid, TS_KID, ts_key.clone()).map(|key| {
                // `stated`, not a pin: this corpus is produced by the in-process prototype
                // log, so there is no operator-reviewed document these profiles came from.
                // The log hashes the statement's own octets as the entry.
                ResolvedTransparencyService::stated(
                    key,
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        },
    ) {
        Ok(()) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}
