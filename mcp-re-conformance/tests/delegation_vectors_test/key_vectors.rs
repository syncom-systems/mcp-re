// SPDX-License-Identifier: Apache-2.0
//! Vectors about which key signed and whether a credential is present: a stripped or
//! lifted credential, a substituted key, key rotation, and tampered response bytes.

use super::credential::credentialless_response;
use super::credential::delegated_response;
use super::credential::good_claims;
use super::credential::good_header;
use super::credential::mint;
use super::credential::tamper_response_signature;
use super::credential::valid_credential;
use super::credential::valid_response;
use super::credential::ResponseSigning;
use super::material::attacker_key;
use super::material::delegated2_key;
use super::material::delegated_key;
use super::material::root_key;
use super::material::DELEGATED2_KID;
use super::material::DELEGATED_KID;
use super::material::ROOT_KID;
use super::policy_vectors::revoked_fixture;
use super::schema::Fixture;
use super::vectors::Case;

/// d10–d15: presence of the credential and which key made the signature.
pub(super) fn presence_and_key_fixtures(case: &Case) -> Vec<Fixture> {
    // delegation required rejects a directly root-signed response
    let direct = credentialless_response(&case.req, &case.ev, &root_key(), ROOT_KID);

    // substituted key: RFC 9421 keyid ≠ delegated_kid
    let valid = valid_credential();
    let wrong_keyid = delegated_response(
        &case.req,
        &ResponseSigning {
            keyid: "some-other-kid",
            ..ResponseSigning::primary(&valid)
        },
    );

    // substituted key: signed by a key other than cnf.jwk
    let non_cnf = delegated_response(
        &case.req,
        &ResponseSigning {
            signing_key: attacker_key,
            ..ResponseSigning::primary(&valid)
        },
    );

    // credential stripped from a delegated response
    let stripped = credentialless_response(&case.req, &case.ev, &delegated_key(), DELEGATED_KID);

    // A trusted-root credential that authorizes DELEGATED2 (and is thus scoped to
    // DELEGATED2's server-signer), swapped onto a response signed by (and whose
    // block names) DELEGATED1. The credential's `mcp_re_server_signer` no longer
    // matches the block's resolved server-signer, so scope binding (§3 step 5)
    // rejects the lifted credential before the step-8 keyid/cnf cross-check.
    let foreign = mint(
        &root_key(),
        &good_header(),
        &good_claims(&delegated2_key(), DELEGATED2_KID),
    );
    let lifted = delegated_response(&case.req, &ResponseSigning::primary(&foreign));

    vec![
        case.nominal(
            "d10_required_rejects_direct_root",
            "mcp-re.delegation_credential_missing",
            &direct,
        ),
        revoked_fixture(case),
        case.nominal(
            "d12_keyid_not_delegated_kid",
            "mcp-re.delegation_key_mismatch",
            &wrong_keyid,
        ),
        case.nominal(
            "d13_signed_by_non_cnf_key",
            "mcp-re.delegation_key_mismatch",
            &non_cnf,
        ),
        case.nominal(
            "d14_credential_stripped",
            "mcp-re.delegation_credential_missing",
            &stripped,
        ),
        case.nominal(
            "d15_credential_lifted_wrong_server_signer",
            "mcp-re.delegation_audience_mismatch",
            &lifted,
        ),
    ]
}

/// d19–d22: a rotation overlap verifies under either successor; tampered bytes do not.
pub(super) fn rotation_and_tamper_fixtures(case: &Case) -> Vec<Fixture> {
    // Key B is a second in-overlap delegated key with its own valid credential, so
    // there is no verification gap across the rotation.
    let cred_b = mint(
        &root_key(),
        &good_header(),
        &good_claims(&delegated2_key(), DELEGATED2_KID),
    );
    let rsp_b = delegated_response(
        &case.req,
        &ResponseSigning {
            signing_key: delegated2_key,
            keyid: DELEGATED2_KID,
            block_signer_kid: DELEGATED2_KID,
            ..ResponseSigning::primary(&cred_b)
        },
    );

    // response body tamper (content-digest floor)
    let mut body_tampered = valid_response(&case.req);
    let last = body_tampered.body.len() - 2;
    body_tampered.body[last] ^= 0x01;

    // response signature-bytes tamper (verify under cnf fails)
    let mut sig_tampered = valid_response(&case.req);
    tamper_response_signature(&mut sig_tampered);

    vec![
        case.nominal("d19_rotation_overlap_key_a", "verify_ok", &case.valid_rsp),
        case.nominal("d20_rotation_overlap_key_b", "verify_ok", &rsp_b),
        case.nominal("d21_body_tamper", "mcp-re.digest_mismatch", &body_tampered),
        case.nominal(
            "d22_response_signature_tamper",
            "mcp-re.delegation_key_mismatch",
            &sig_tampered,
        ),
    ]
}
