//! Whether an OCSP answer is current and is an answer to THIS request: the freshness window
//! of a `SingleResponse` and the request-nonce echo.
//!
//! A captured, responder-signed `good` must not be replayable once its window has closed, and
//! must not be replayable under another request's nonce.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use x509_ocsp::BasicOcspResponse;
use x509_ocsp::SingleResponse;

/// The freshness skew tolerance: a few minutes absorbs clock drift between the
/// proxy and the responder without widening the window enough to matter for
/// revocation latency. `thisUpdate` may be up to this far in the future, and
/// `nextUpdate` up to this far in the past, before the response is rejected.
const OCSP_FRESHNESS_SKEW: Duration = Duration::from_secs(300);

/// The maximum age a response may have relative to its `thisUpdate`, applied as
/// an absolute upper bound on acceptance EVEN WHEN `nextUpdate` is absent. RFC
/// 6960 permits responders to omit `nextUpdate` (and to ignore the request
/// nonce), which would otherwise let a captured responder-signed `good` be
/// replayed by an active network attacker indefinitely — keeping a since-revoked
/// client admitted and defeating the online check's purpose of bounding
/// revocation latency. Capping acceptance at `thisUpdate + max_response_age (+
/// skew)` bounds that replay window. One day is comfortably longer than any
/// well-configured responder's refresh interval while still bounding latency.
const OCSP_MAX_RESPONSE_AGE: Duration = Duration::from_secs(86_400);

/// The end of `single`'s acceptance window under this module's skew and maximum age, or
/// `None` when it is not fresh at `now`. See [`acceptance_bound`] for the rule.
pub(super) fn accepted_until(single: &SingleResponse, now: SystemTime) -> Option<Duration> {
    acceptance_bound(single, now, OCSP_FRESHNESS_SKEW, OCSP_MAX_RESPONSE_AGE)
}

/// The end of `single`'s acceptance window, as a `Duration` since the Unix epoch, when it is
/// fresh at `now` within `skew` — `None` otherwise. Fresh means `now >= thisUpdate - skew`
/// and `now <= upper + skew`, where `upper` is `nextUpdate` when present, capped at
/// `thisUpdate + max_age`; the returned bound is `upper + skew`. A response with no
/// `nextUpdate` therefore still has an absolute bound of `thisUpdate + max_age + skew`, so
/// a captured responder-signed response cannot be replayed indefinitely even when the
/// responder omits `nextUpdate` and ignores the nonce. Pure.
fn acceptance_bound(
    single: &SingleResponse,
    now: SystemTime,
    skew: Duration,
    max_age: Duration,
) -> Option<Duration> {
    let now_unix = system_time_to_unix(now)?;
    let this_update = single.this_update.0.to_unix_duration();
    if now_unix.saturating_add(skew) < this_update {
        return None;
    }
    let age_cap = this_update.saturating_add(max_age);
    let upper = match &single.next_update {
        Some(next_update) => next_update.0.to_unix_duration().min(age_cap),
        None => age_cap,
    };
    let bound = upper.saturating_add(skew);
    (now_unix <= bound).then_some(bound)
}

/// `now` as a `Duration` since the Unix epoch, or `None` if it predates the epoch
/// (which would make freshness comparisons meaningless — fail closed).
pub(super) fn system_time_to_unix(now: SystemTime) -> Option<Duration> {
    now.duration_since(UNIX_EPOCH).ok()
}

/// Whether the response nonce is acceptable: either the responder echoed no nonce
/// (permitted — many responders do not honor nonces) OR it echoed exactly our
/// `request_nonce`. A present-but-different nonce is a replay/substitution. Pure.
pub(super) fn nonce_ok(basic: &BasicOcspResponse, request_nonce: &[u8]) -> bool {
    match basic.nonce() {
        None => true,
        Some(echoed) => echoed.0.as_bytes() == request_nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::acceptance_bound;
    use super::accepted_until;
    use super::nonce_ok;
    use super::OCSP_FRESHNESS_SKEW;
    use super::OCSP_MAX_RESPONSE_AGE;
    use crate::ocsp::pipeline::tests::at;
    use crate::ocsp::pipeline::tests::build_fixture;
    use crate::ocsp::pipeline::tests::gtime;
    use crate::ocsp::pipeline::tests::ResponseFixture;
    use crate::ocsp::pipeline::tests::Ymd;

    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use x509_ocsp::SingleResponse;

    /// The only `SingleResponse` of an unsigned response built per `fixture`.
    fn single_of(fixture: ResponseFixture) -> SingleResponse {
        let basic = build_fixture(fixture).basic();
        basic.tbs_response_data.responses[0].clone()
    }

    /// Whether `single` is fresh at `now` — `accepted_until` answering at all.
    fn is_fresh(single: &SingleResponse, now: SystemTime) -> bool {
        accepted_until(single, now).is_some()
    }

    #[test]
    fn freshness_window_enforced() {
        // thisUpdate=Jan1, nextUpdate=Jan2; with skew=5m the valid window is
        // ~[Jan1-5m, Jan2+5m].
        let single = single_of(ResponseFixture::good());
        assert!(is_fresh(&single, at(Ymd(2024, 1, 1))), "within window");
        assert!(
            !is_fresh(&single, at(Ymd(2023, 12, 31))),
            "before thisUpdate (beyond skew) is not fresh"
        );
        assert!(
            !is_fresh(&single, at(Ymd(2024, 6, 1))),
            "after nextUpdate (beyond skew) is not fresh"
        );
    }

    #[test]
    fn freshness_skew_tolerated() {
        let single = single_of(ResponseFixture {
            next_update: Some(gtime(Ymd(2024, 1, 1))),
            ..ResponseFixture::good()
        });
        // 2 minutes before thisUpdate is within the 5-minute skew.
        let just_before = at(Ymd(2024, 1, 1)) - Duration::from_secs(120);
        assert!(is_fresh(&single, just_before));
    }

    #[test]
    fn freshness_capped_when_no_next_update() {
        // A responder-signed `good` with thisUpdate=Jan1 and NO nextUpdate (RFC
        // 6960 permits omission). Without an absolute cap, this could be replayed
        // indefinitely; with the max-age cap it must be rejected once it is older
        // than thisUpdate + OCSP_MAX_RESPONSE_AGE (+ skew).
        let single = single_of(ResponseFixture {
            next_update: None,
            ..ResponseFixture::good()
        });
        assert!(
            is_fresh(&single, at(Ymd(2024, 1, 1))),
            "no-nextUpdate response at thisUpdate is fresh"
        );
        // Within the cap (12h after thisUpdate, cap is 24h): still fresh.
        let within = at(Ymd(2024, 1, 1)) + Duration::from_secs(12 * 3600);
        assert!(
            is_fresh(&single, within),
            "no-nextUpdate response within max-age cap is fresh"
        );
        // Beyond thisUpdate + max_age + skew: must be rejected. This is the
        // regression — before the cap, a no-nextUpdate response was accepted here.
        let replayed = at(Ymd(2024, 1, 1))
            + OCSP_MAX_RESPONSE_AGE
            + OCSP_FRESHNESS_SKEW
            + Duration::from_secs(60);
        assert!(
            !is_fresh(&single, replayed),
            "no-nextUpdate response older than the max-age cap must be rejected (anti-replay)"
        );
    }

    #[test]
    fn nonce_match_required_when_present() {
        let req = b"the-request-nonce".to_vec();
        let basic_echoing = |echo_nonce: Option<Vec<u8>>| {
            build_fixture(ResponseFixture {
                next_update: None,
                echo_nonce,
                ..ResponseFixture::good()
            })
            .basic()
        };
        assert!(
            nonce_ok(&basic_echoing(Some(req.clone())), &req),
            "echoed == request → ok"
        );
        assert!(
            !nonce_ok(&basic_echoing(Some(b"a-different-nonce".to_vec())), &req),
            "echoed != request → reject"
        );
        assert!(
            nonce_ok(&basic_echoing(None), &req),
            "no echoed nonce is permitted (responder may not honor nonces)"
        );
    }

    /// The bound `verify_and_map_response` stores is the one `acceptance_bound` computes,
    /// so an answer taken at T is refused once T's window has closed.
    #[test]
    fn a_verified_answer_is_admitted_only_inside_its_acceptance_window() {
        let single = single_of(ResponseFixture::good());
        let bound = acceptance_bound(
            &single,
            at(Ymd(2024, 1, 1)),
            OCSP_FRESHNESS_SKEW,
            OCSP_MAX_RESPONSE_AGE,
        )
        .expect("fresh at thisUpdate");
        assert_eq!(
            bound,
            at(Ymd(2024, 1, 2)).duration_since(UNIX_EPOCH).unwrap() + OCSP_FRESHNESS_SKEW,
            "nextUpdate plus skew"
        );
        assert_eq!(
            accepted_until(
                &single,
                at(Ymd(2024, 1, 2)) + OCSP_FRESHNESS_SKEW + Duration::from_secs(1)
            ),
            None
        );
    }
}
