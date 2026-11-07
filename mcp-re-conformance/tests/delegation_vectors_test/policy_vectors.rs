// SPDX-License-Identifier: Apache-2.0
//! Vectors where the credential is valid and the verifier's policy decides: the same
//! frozen response, accepted or refused by who is asking and which epochs it accepts.

use super::material::DELEGATED_KID;
use super::material::EPOCH;
use super::material::NEXT_EPOCH;
use super::schema::DelegationCheck;
use super::schema::Fixture;
use super::schema::Verdict;
use super::vectors::Case;

fn policy(edit: impl FnOnce(&mut DelegationCheck)) -> DelegationCheck {
    let mut check = DelegationCheck::nominal();
    edit(&mut check);
    check
}

/// d06–d09: audience, scope and trust-epoch policy over the valid response.
pub(super) fn policy_fixtures(case: &Case) -> Vec<Fixture> {
    let cases = [
        // A VALID credential, rejected because THIS verifier is not in its audience.
        (
            "d06_verifier_not_in_aud",
            "mcp-re.delegation_audience_mismatch",
            policy(|c| c.verifier_audiences = vec!["some-other-verifier".into()]),
        ),
        // The credential is scoped to a different service.
        (
            "d07_audience_scope_mismatch",
            "mcp-re.delegation_audience_mismatch",
            policy(|c| c.expected_audience_hash = "different-scope".into()),
        ),
        (
            "d08_trust_epoch_stale",
            "mcp-re.delegation_trust_epoch_stale",
            policy(|c| c.accepted_epochs = vec![NEXT_EPOCH.into()]),
        ),
        // Same valid credential (epoch = EPOCH), accepted only because the verifier
        // explicitly runs { current = NEXT_EPOCH, previous = EPOCH }.
        (
            "d09_bounded_rollout_previous_epoch",
            "verify_ok",
            policy(|c| c.accepted_epochs = vec![NEXT_EPOCH.into(), EPOCH.into()]),
        ),
    ];
    cases
        .into_iter()
        .map(|(name, expected, check)| {
            case.fixture(Verdict { name, expected }, &case.valid_rsp, check)
        })
        .collect()
}

/// d11: the delegated key is on the verifier's revocation list.
pub(super) fn revoked_fixture(case: &Case) -> Fixture {
    case.fixture(
        Verdict {
            name: "d11_revoked_delegated_key",
            expected: "mcp-re.delegation_revoked",
        },
        &case.valid_rsp,
        policy(|c| c.revoked_kids = vec![DELEGATED_KID.into()]),
    )
}
