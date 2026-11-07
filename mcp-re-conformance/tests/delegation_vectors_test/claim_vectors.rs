// SPDX-License-Identifier: Apache-2.0
//! Vectors whose credential is wrong: a bad claim, a bad header, or a bad issuer
//! signature, all verified under the nominal policy.

use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpResponse;

use super::credential::delegated_response;
use super::credential::good_claims;
use super::credential::good_header;
use super::credential::mint;
use super::credential::ResponseSigning;
use super::material::attacker_key;
use super::material::delegated_key;
use super::material::root_key;
use super::material::CREATED;
use super::material::DELEGATED_KID;
use super::material::NOW;
use super::schema::Fixture;
use super::vectors::Case;

type ClaimMutation = fn(&mut DelegationClaims);

/// A response carrying a credential minted from `header` and `claims`.
fn response_for(case: &Case, header: &DelegationHeader, claims: &DelegationClaims) -> HttpResponse {
    let credential = mint(&root_key(), header, claims);
    delegated_response(&case.req, &ResponseSigning::primary(&credential))
}

/// d01–d05: the valid vector, then one claim at a time made wrong.
pub(super) fn claim_fixtures(case: &Case) -> Vec<Fixture> {
    let mutated: [(&str, &str, ClaimMutation); 4] = [
        // exp < now
        (
            "d02_credential_expired",
            "mcp-re.delegation_credential_expired",
            |c| {
                c.nbf = CREATED - 20_000;
                c.exp = CREATED - 10_000;
            },
        ),
        // now < nbf
        (
            "d03_not_yet_valid",
            "mcp-re.delegation_credential_expired",
            |c| {
                c.nbf = NOW + 10_000;
                c.exp = NOW + 20_000;
            },
        ),
        (
            "d04_key_use_invalid",
            "mcp-re.delegation_key_use_invalid",
            |c| c.mcp_re_key_use = "request-signing".into(),
        ),
        (
            "d05_profile_mismatch",
            "mcp-re.delegation_profile_mismatch",
            |c| c.mcp_re_profile = "some-other-profile".into(),
        ),
    ];
    let mut fixtures = vec![case.nominal("d01_valid", "verify_ok", &case.valid_rsp)];
    for (name, expected, mutate) in mutated {
        let mut claims = good_claims(&delegated_key(), DELEGATED_KID);
        mutate(&mut claims);
        let rsp = response_for(case, &good_header(), &claims);
        fixtures.push(case.nominal(name, expected, &rsp));
    }
    fixtures
}

/// d16–d18: a credential the root did not honestly issue.
pub(super) fn issuer_fixtures(case: &Case) -> Vec<Fixture> {
    // issuer_untrusted
    let mut untrusted_header = good_header();
    untrusted_header.kid = "untrusted-root".into();
    let mut untrusted_claims = good_claims(&delegated_key(), DELEGATED_KID);
    untrusted_claims.issuer_kid = "untrusted-root".into();
    let untrusted = response_for(case, &untrusted_header, &untrusted_claims);

    // wrong_alg (header alg ≠ EdDSA, incl. `none`)
    let mut none_header = good_header();
    none_header.alg = "none".into();
    let wrong_alg = response_for(
        case,
        &none_header,
        &good_claims(&delegated_key(), DELEGATED_KID),
    );

    // forged root signature (claims a trusted issuer_kid)
    let forged = mint(
        &attacker_key(),
        &good_header(),
        &good_claims(&delegated_key(), DELEGATED_KID),
    );
    let forged = delegated_response(&case.req, &ResponseSigning::primary(&forged));

    vec![
        case.nominal(
            "d16_issuer_untrusted",
            "mcp-re.delegation_issuer_untrusted",
            &untrusted,
        ),
        case.nominal(
            "d17_wrong_alg",
            "mcp-re.delegation_credential_invalid",
            &wrong_alg,
        ),
        case.nominal(
            "d18_forged_root_signature",
            "mcp-re.delegation_credential_invalid",
            &forged,
        ),
    ]
}
