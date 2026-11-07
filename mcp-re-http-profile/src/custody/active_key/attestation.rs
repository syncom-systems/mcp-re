// SPDX-License-Identifier: Apache-2.0
//! What a returned credential must state, relative to the issuance that asked for it. Each
//! predicate refuses with [`HttpProfileError::DelegationCredentialInvalid`]; the caller maps
//! that to the [`IssuanceRefusal`](super::IssuanceRefusal) naming why it is not this
//! issuance's answer.

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::delegation::delegated_key_of;
use crate::delegation::DelegationClaims;
use crate::error::HttpProfileError;

const INVALID: HttpProfileError = HttpProfileError::DelegationCredentialInvalid;

/// The delegated key identity and its binding to the key actually held. `cnf` is the rule that
/// a wrong key type, a wrong curve, or a `jwk.kid` that is not the credential's own
/// `delegated_kid` is an invalid credential; it belongs to the verifier and is borrowed rather
/// than restated. What is added here is the half a verifier cannot check: that the attested
/// key is the one in this process.
pub(super) fn holds_the_key(
    claims: &DelegationClaims,
    key: &SigningKey,
) -> Result<(), HttpProfileError> {
    if delegated_key_of(claims)?.to_bytes() != key.public_key().to_bytes() {
        return Err(INVALID);
    }
    Ok(())
}

/// The identity the response block will carry is the one the credential states, and its
/// `keyid` is the delegated key's own id, not merely whatever the join spells.
pub(super) fn names_the_identity(
    claims: &DelegationClaims,
    server_signer: &ActorIdentity,
) -> Result<(), HttpProfileError> {
    if claims.mcp_re_server_signer != server_signer.actor_id()
        || server_signer.keyid != claims.delegated_kid
    {
        return Err(INVALID);
    }
    Ok(())
}

/// The static delegation context: issuer, audience, profile, scope, epoch, key use, `jti`,
/// `cnf`. Exempt are the window (`nbf`/`exp`), which the root owns within the bounds of
/// [`window_is_admissible`], and `iat`, the root's own issuance stamp: no verifier stores or
/// consumes it. The header needs no comparison: `root_signed` pinned `typ` and `alg` and
/// resolved its `kid` as the requested root's.
pub(super) fn echoes_the_request(
    claims: &DelegationClaims,
    requested: &DelegationClaims,
) -> Result<(), HttpProfileError> {
    let mut as_requested = requested.clone();
    as_requested.iat = claims.iat;
    as_requested.nbf = claims.nbf;
    as_requested.exp = claims.exp;
    if *claims != as_requested {
        return Err(INVALID);
    }
    Ok(())
}

/// The window the root issued, against the one requested.
///
/// - The temporal relation itself: a window that is empty or inverted is not a narrower
///   credential, it is an incoherent one, and `exp` is what the whole fail-closed path is
///   decided on.
/// - Activation: the root owns the window's edges, but a key whose `nbf` is later than the
///   instant it was requested at would be published and served at once while every verifier
///   still refuses it. A root whose clock runs ahead therefore FAILS the issuance, and the
///   predecessor keeps serving through the overlap.
/// - The root may clamp the window, never extend it: an `exp` past the one requested would
///   serve this key beyond the TTL the deployment chose. And the window must be open at the
///   instant it was requested, or the issuance adopts a key that is already expired.
pub(super) fn window_is_admissible(
    claims: &DelegationClaims,
    requested: &DelegationClaims,
) -> Result<(), HttpProfileError> {
    let conditions = [
        claims.nbf < claims.exp,
        claims.nbf <= requested.nbf,
        claims.exp <= requested.exp,
        claims.exp > requested.nbf,
    ];
    if conditions.into_iter().all(|holds| holds) {
        Ok(())
    } else {
        Err(INVALID)
    }
}
