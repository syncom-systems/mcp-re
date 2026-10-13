// SPDX-License-Identifier: Apache-2.0
//! The temporal claims of a root-signed statement, and the one rule for whether an instant
//! is inside them.

/// Why an instant is not inside a statement's temporal claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowDefect {
    /// `exp <= nbf`: the issuer said nothing about validity at all. Refused rather than
    /// read as an empty window, and refused before the edges are consulted.
    Degenerate,
    /// `now` is before `nbf` or at or after `exp`, each edge widened by the skew.
    Outside,
    /// `iat` is ahead of `now` by more than the skew. `iat` is a claim independent of
    /// `[nbf, exp]`, and every age a verifier measures from it is `now - iat` against an
    /// upper bound only, so a future issuance would pass every such bound for the
    /// statement's whole lifetime.
    IssuedInTheFuture,
}

/// The `iat`, `nbf` and `exp` claims of one statement (RFC 7519 §4.1.4–4.1.6).
///
/// # The edge rule
///
/// With a skew tolerance `s`, `now` is inside the window iff
///
/// ```text
/// nbf < exp  and  nbf - s <= now < exp + s  and  iat <= now + s
/// ```
///
/// The upper edge is exclusive, as RFC 7519 §4.1.4 states it: the current time must be
/// strictly before `exp`. `exp + s` is therefore the first stale instant, not the last
/// fresh one. The claim-side sums saturate because the operands come straight out of a
/// signed payload, so an extreme claim clamps instead of wrapping or panicking; a clamped
/// edge refuses at least as much as the exact one would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaimWindow {
    pub(crate) iat: i64,
    pub(crate) nbf: i64,
    pub(crate) exp: i64,
}

impl ClaimWindow {
    /// Whether `now` is inside this window under a skew tolerance of `skew` seconds. A
    /// negative tolerance narrows both edges.
    pub(crate) fn check(self, now: i64, skew: i64) -> Result<(), WindowDefect> {
        if self.exp <= self.nbf {
            return Err(WindowDefect::Degenerate);
        }
        if self.nbf.saturating_sub(skew) > now || self.exp.saturating_add(skew) <= now {
            return Err(WindowDefect::Outside);
        }
        if self.iat > now.saturating_add(skew) {
            return Err(WindowDefect::IssuedInTheFuture);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const SKEW: i64 = 30;

    fn window(nbf: i64, exp: i64) -> ClaimWindow {
        ClaimWindow { iat: nbf, nbf, exp }
    }

    /// The upper edge is exclusive: `exp + skew` is the first stale instant.
    #[test]
    fn exp_plus_skew_is_the_first_stale_instant() {
        let w = window(NOW - 400, NOW - SKEW);
        assert_eq!(w.check(NOW, SKEW), Err(WindowDefect::Outside));
        assert_eq!(w.check(NOW - 1, SKEW), Ok(()));
    }

    /// The lower edge is inclusive: `nbf - skew` is the first fresh instant.
    #[test]
    fn nbf_minus_skew_is_the_first_fresh_instant() {
        let w = window(NOW + SKEW, NOW + 400);
        assert_eq!(w.check(NOW, SKEW), Ok(()));
        assert_eq!(w.check(NOW - 1, SKEW), Err(WindowDefect::Outside));
    }

    #[test]
    fn a_degenerate_window_is_refused_whatever_the_skew() {
        for (nbf, exp) in [(NOW, NOW), (NOW + 1, NOW)] {
            assert_eq!(
                window(nbf, exp).check(NOW, 1_000_000),
                Err(WindowDefect::Degenerate)
            );
        }
    }

    #[test]
    fn an_issuance_dated_ahead_of_now_is_refused_beyond_the_skew() {
        let mut w = window(NOW - 10, NOW + 7_200);
        w.iat = NOW + SKEW;
        assert_eq!(w.check(NOW, SKEW), Ok(()));
        w.iat = NOW + SKEW + 1;
        assert_eq!(w.check(NOW, SKEW), Err(WindowDefect::IssuedInTheFuture));
    }

    #[test]
    fn a_negative_skew_narrows_both_edges() {
        let w = window(NOW, NOW + 100);
        assert_eq!(w.check(NOW, -1), Err(WindowDefect::Outside));
        assert_eq!(w.check(NOW + 99, -1), Err(WindowDefect::Outside));
        assert_eq!(w.check(NOW + 50, -1), Ok(()));
    }

    #[test]
    fn extreme_claims_clamp_instead_of_wrapping() {
        assert_eq!(
            window(i64::MIN, i64::MAX).check(NOW, SKEW),
            Ok(()),
            "the widest window admits an ordinary instant"
        );
        let mut w = window(i64::MIN, i64::MAX);
        w.iat = i64::MAX;
        assert_eq!(w.check(NOW, SKEW), Err(WindowDefect::IssuedInTheFuture));
        assert_eq!(
            window(i64::MAX - 1, i64::MAX).check(i64::MAX, SKEW),
            Err(WindowDefect::Outside),
            "a clamped upper edge still refuses"
        );
    }
}
