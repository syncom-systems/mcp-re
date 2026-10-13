// SPDX-License-Identifier: Apache-2.0
//! The dispatch seam's two products, and what possessing one means.
//!
//! ## What this owns
//!
//! One fact: **a dispatch product is evidence of the preparation that produced it.**
//!
//! [`DispatchOutcome::continuation_verified`] is the Verus-proved postcondition of
//! `prepare_http_dispatch` (`http_profile.continuation_unbypassability`): if the request
//! carried a continuation and preparation returned `Ok`, that continuation WAS verified
//! against the caller-retained bases.
//!
//! ## The defect this module exists to remove
//!
//! A `pub` field let a struct literal anywhere in the workspace supply that proved fact
//! with no proof at all. Nothing about the theorem was false — it quantifies over what the
//! proved function RETURNS — and nothing about an arbitrary value of the type was true,
//! which is the whole distance between a theorem and a field.
//!
//! So the representation is private to this module. [`PreparedDispatch`] is the sole
//! product of a successful preparation and [`DispatchOutcome`] is the sole product of a
//! `PreparedDispatch`. Neither has a public constructor: the one constructor is
//! `pub(in crate::dispatch)` and CONSUMES the [`ReplayTierAdmitted`] witness, so the
//! posture decision, the preparation and the product are one chain rather than three
//! values a caller assembles.
//!
//! ## Why the posture travels with the product
//!
//! [`ReplayTierAdmitted`] records WHICH arm decided the replay store's class, and nothing
//! consumed that fact. A dispatch product is its natural consumer: a record stating that a
//! request was admitted can now state the posture it was admitted under, instead of
//! re-deriving it from a configuration value read somewhere else — which would be a second
//! opinion about a decision this seam already took.
//!
//! The arm itself stays private. [`DispatchOutcome::admitting_posture`] is a sentence, not
//! a branchable tag, because no consumer decides anything from it; the moment one needs to,
//! that is a new decision with an owner, not a field read.

use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;

use super::replay_posture::PostureDecision;
use super::DispatchError;
use super::ReplayTierAdmitted;
use crate::replay::HttpReplayKey;
use crate::replay::ReplayKey;

/// Dispatch steps 1–3, completed: the store's durability posture was decided, the
/// five-tuple [`HttpReplayKey`] was built from the verified evidence, and any MRTR
/// continuation the request carried verified against the caller-retained bases.
///
/// What it is NOT is an admission. The nonce is spent by whoever holds the store — the
/// sync dispatcher against a `&dyn mcp_re_core::ReplayCache`, the async data plane against
/// its awaited tier — so the one side-effecting step cannot live here. Its answer is read
/// here, by [`Self::admit`].
///
/// The representation is private, so the proved `continuation_verified` cannot be supplied
/// by anyone who did not prepare a dispatch. The literal names every field, so the only
/// refusal is their privacy (E0451); structural probe S33 compiles it and requires that code,
/// and requires it to compile once the fields are public:
///
/// ```compile_fail
/// use mcp_re_http_profile::dispatch::PreparedDispatch;
/// fn fabricate(replay_key: mcp_re_http_profile::HttpReplayKey) -> PreparedDispatch {
///     PreparedDispatch {
///         replay_key,
///         continuation_verified: true,
///         posture: todo!(),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PreparedDispatch {
    replay_key: HttpReplayKey,
    continuation_verified: bool,
    posture: PostureDecision,
}

impl PreparedDispatch {
    /// The only constructor, and it consumes the posture witness.
    ///
    /// `pub(in crate::dispatch)`: the legitimate producer is
    /// [`ReplayTierAdmitted::prepare`], which is in this subtree. Nothing
    /// outside it — including `mcp-re-proxy`, which used to build the outcome itself — can
    /// name this function or the fields it fills.
    ///
    /// Taking the witness BY VALUE is what makes the chain single-use: one posture
    /// decision admits one preparation and yields one product.
    pub(in crate::dispatch) fn from_admitted(
        admitted: ReplayTierAdmitted,
        replay_key: HttpReplayKey,
        continuation_verified: bool,
    ) -> PreparedDispatch {
        PreparedDispatch {
            replay_key,
            continuation_verified,
            posture: admitted.posture(),
        }
    }

    /// The five-tuple to admit.
    ///
    /// Borrowed rather than moved out: admission reads the key and the product keeps it, so
    /// a caller cannot admit one key and report another.
    pub fn replay_key(&self) -> &HttpReplayKey {
        &self.replay_key
    }

    /// The key the authoritative async tier admits, for a request expiring at
    /// `expires_at_unix`.
    ///
    /// The only public way to a [`ReplayKey`]: its burn and budget identities come from the
    /// five-tuple this preparation built out of the verified product, never from a caller.
    pub fn to_replay_key(&self, expires_at_unix: i64) -> ReplayKey {
        self.replay_key.to_replay_key(expires_at_unix)
    }

    /// See [`DispatchOutcome::continuation_verified`].
    pub fn continuation_verified(&self) -> bool {
        self.continuation_verified
    }

    /// See [`DispatchOutcome::admitting_posture`].
    pub fn admitting_posture(&self) -> &'static str {
        self.posture.description()
    }

    /// The replay store's answer for [`Self::replay_key`], read once for both serving
    /// paths: `Fresh` becomes the outcome, `Replay` is [`DispatchError::ReplayDetected`],
    /// and an error is an outage, [`DispatchError::ReplayCacheUnavailable`], never a replay.
    pub fn admit(
        self,
        answer: Result<ReplayDecision, ReplayCacheError>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match answer {
            Ok(ReplayDecision::Fresh) => Ok(DispatchOutcome {
                replay_key: self.replay_key,
                continuation_verified: self.continuation_verified,
                posture: self.posture,
            }),
            Ok(ReplayDecision::Replay) => Err(DispatchError::ReplayDetected),
            Err(_) => Err(DispatchError::ReplayCacheUnavailable),
        }
    }
}

/// The successful product of a dispatch: the admitted replay key, whether an MRTR
/// continuation was present and verified, and the posture the store class was decided
/// under.
///
/// Every inhabitant came from a [`PreparedDispatch`] whose replay store answered `Fresh`,
/// and that preparation came from a posture decision. A struct literal is not an
/// inhabitant (E0451; structural probe S34):
///
/// ```compile_fail
/// use mcp_re_http_profile::DispatchOutcome;
/// fn fabricate(replay_key: mcp_re_http_profile::HttpReplayKey) -> DispatchOutcome {
///     DispatchOutcome {
///         replay_key,
///         continuation_verified: true,
///         posture: todo!(),
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    replay_key: HttpReplayKey,
    continuation_verified: bool,
    posture: PostureDecision,
}

impl DispatchOutcome {
    /// The five-tuple admitted to the replay cache, for audit and correlation.
    pub fn replay_key(&self) -> &HttpReplayKey {
        &self.replay_key
    }

    /// `true` iff the request carried a continuation that verified against the retained
    /// bases; `false` for an ordinary first-leg request.
    ///
    /// The proved half is the direction that matters: a request carrying a continuation
    /// cannot reach a successful dispatch with this `false`, because the only preparation
    /// that can produce one refuses first.
    pub fn continuation_verified(&self) -> bool {
        self.continuation_verified
    }

    /// What the posture decision that admitted this dispatch said, in its own words.
    ///
    /// A sentence rather than a tag, deliberately: the two arms mean materially different
    /// things and no consumer branches on them. An audit line that flattened them would
    /// claim a fleet-strict clearance for a deployment that never asked for one.
    pub fn admitting_posture(&self) -> &'static str {
        self.posture.description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> HttpReplayKey {
        HttpReplayKey {
            profile_id: "mcp-re-http-v1".into(),
            signature_label: "mcp-re".into(),
            actor_id: "client:example.com:did%3Aexample%3Aa:k".into(),
            audience_hash: "AAAA".into(),
            nonce: "nonce-1".into(),
        }
    }

    fn prepared(posture: PostureDecision, continuation_verified: bool) -> PreparedDispatch {
        PreparedDispatch {
            replay_key: key(),
            continuation_verified,
            posture,
        }
    }

    fn fresh(p: PreparedDispatch) -> DispatchOutcome {
        p.admit(Ok(ReplayDecision::Fresh))
            .expect("a fresh admission is an outcome")
    }

    #[test]
    fn the_admitted_outcome_carries_the_preparation_unchanged() {
        // The product is evidence ABOUT a preparation, so a conversion that quietly reset
        // a field would be the same defect as the public literal, one level down.
        let outcome = fresh(prepared(PostureDecision::StoreClassAdmitted, true));
        assert_eq!(outcome.replay_key(), &key());
        assert!(outcome.continuation_verified());
    }

    #[test]
    fn a_replay_answer_is_refused_as_a_replay() {
        let refusal = prepared(PostureDecision::StoreClassAdmitted, false)
            .admit(Ok(ReplayDecision::Replay))
            .expect_err("an already-admitted key must not become an outcome");
        assert_eq!(refusal, DispatchError::ReplayDetected);
    }

    #[test]
    fn a_store_that_did_not_answer_is_an_outage_and_never_a_replay() {
        // "Already served" and "nothing was established" are opposite advice to a caller,
        // so the two refusals must stay distinct, and neither may admit.
        let refusal = prepared(PostureDecision::StoreClassAdmitted, false)
            .admit(Err(ReplayCacheError::Unavailable {
                details: "connection refused".into(),
            }))
            .expect_err("an unanswered admission must not become an outcome");
        assert_eq!(refusal, DispatchError::ReplayCacheUnavailable);
        assert_ne!(refusal, DispatchError::ReplayDetected);
    }

    #[test]
    fn a_first_leg_preparation_reports_no_continuation() {
        // The positive control for the flag: it is not a constant true.
        let outcome = fresh(prepared(PostureDecision::StoreClassNotRequired, false));
        assert!(!outcome.continuation_verified());
    }

    #[test]
    fn the_outcome_states_which_posture_admitted_it() {
        let strict = fresh(prepared(PostureDecision::StoreClassAdmitted, false));
        let lax = fresh(prepared(PostureDecision::StoreClassNotRequired, false));
        assert_ne!(strict.admitting_posture(), lax.admitting_posture());
        assert!(strict.admitting_posture().contains("fleet-strict"));
        assert!(lax.admitting_posture().contains("not required"));
    }

    #[test]
    fn the_prepared_product_reports_the_same_facts_as_the_outcome_it_becomes() {
        // `replay_key()` is read BEFORE admission and the outcome is read after; a
        // consumer comparing the two is comparing one value, not two.
        let p = prepared(PostureDecision::StoreClassAdmitted, true);
        let key_before = p.replay_key().clone();
        let flag_before = p.continuation_verified();
        let posture_before = p.admitting_posture();
        let after = fresh(p);
        assert_eq!(&key_before, after.replay_key());
        assert_eq!(flag_before, after.continuation_verified());
        assert_eq!(posture_before, after.admitting_posture());
    }
}
