// SPDX-License-Identifier: Apache-2.0
//! The arguments of one verification call, and the trust they are read into.

use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::DelegatedResponseTrust;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_core::MaxClockSkew;

use crate::BindingError;
use crate::PinnedIssuer;

/// One answer to verify against the request this client sent.
///
/// The trust inputs: the pinned root issuer, the audience scope (`verifier_audiences` and
/// `expected_audience_hash`), the accepted trust epochs, and the client's static denylist,
/// any mix of delegated kid, issuer kid or credential `jti`; an empty list is the explicit
/// TTL-only posture. `max_clock_skew` and `now` are seconds; each host converts its own
/// number type into them before this value exists. A `max_clock_skew` outside
/// `0..=`[`MaxClockSkew::BOUND_SECS`] is refused, as the sidecar's configuration refuses it,
/// rather than clamped into a tolerance the caller did not ask for.
#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub response: HttpResponse,
    pub request: HttpRequest,
    pub issuer: PinnedIssuer,
    pub verifier_audiences: Vec<String>,
    pub expected_audience_hash: String,
    pub accepted_epochs: Vec<String>,
    pub max_clock_skew: i64,
    pub revoked_identifiers: Vec<String>,
    pub now: i64,
}

/// What a verification check is handed: the answer, the request it must bind to, the
/// composed trust, the delegation policy, and the time it is judged at.
pub(crate) struct Judged<'a> {
    pub(crate) response: &'a HttpResponse,
    pub(crate) request: HttpRequest,
    pub(crate) trust: &'a CompositeResponseTrust<'a>,
    pub(crate) policy: &'a DelegationPolicy,
    pub(crate) now: i64,
}

impl VerifyArgs {
    /// Read the trust inputs and run `check` under them: the pinned anchor (whose identity
    /// is refused before any evidence is read), the skew, the denylist, and the delegation
    /// policy.
    pub(crate) fn judge<T>(
        self,
        check: impl FnOnce(Judged<'_>) -> Result<T, HttpProfileError>,
    ) -> Result<T, BindingError> {
        let anchor = self.issuer.anchor()?;
        let skew = MaxClockSkew::new(self.max_clock_skew).ok_or_else(|| {
            BindingError::Local(format!(
                "max_clock_skew {} is outside 0..={} seconds",
                self.max_clock_skew,
                MaxClockSkew::BOUND_SECS
            ))
        })?;
        let resolve = |kid: &str, slot: SignerSlot, at: i64| anchor.resolve_issuer(kid, slot, at);
        let revocation = StaticRevocationList::from_identifiers(self.revoked_identifiers);
        let trust = CompositeResponseTrust::new(&resolve, &revocation);
        let policy = DelegationPolicy::new(
            self.verifier_audiences,
            &self.expected_audience_hash,
            self.accepted_epochs,
            skew,
        );
        Ok(check(Judged {
            response: &self.response,
            request: self.request,
            trust: &trust,
            policy: &policy,
            now: self.now,
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::VerifyArgs;
    use crate::BindingError;
    use crate::IssuerField;
    use crate::PinnedIssuer;
    use mcp_re_client_core::HttpProfileError;
    use mcp_re_client_core::HttpRequest;
    use mcp_re_client_core::HttpResponse;
    use mcp_re_core::SigningKey;

    fn args(role: &str) -> VerifyArgs {
        VerifyArgs {
            response: HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            },
            request: HttpRequest {
                method: "POST".into(),
                target_uri: "https://example.com/mcp".into(),
                headers: Vec::new(),
                body: b"{}".to_vec(),
            },
            issuer: PinnedIssuer {
                key_id: "root-1".into(),
                pubkey_b64url: SigningKey::from_seed_bytes(&[7u8; 32])
                    .public_key()
                    .to_b64url(),
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server-1".into(),
                retired_until: None,
            },
            verifier_audiences: vec!["aud".into()],
            expected_audience_hash: "h".into(),
            accepted_epochs: vec!["e1".into()],
            max_clock_skew: 30,
            revoked_identifiers: Vec::new(),
            now: 1_000,
        }
    }

    /// The SDK refuses a skew the sidecar's configuration refuses: the bound is accepted,
    /// one second past it is a local refusal naming the bound, and the check never runs.
    #[test]
    fn a_skew_past_the_bound_is_refused_and_the_bound_is_accepted() {
        let mut at_bound = args("server");
        at_bound.max_clock_skew = mcp_re_core::MaxClockSkew::BOUND_SECS;
        at_bound
            .judge(|_| Ok(()))
            .expect("the bound itself is a skew");

        for past in [mcp_re_core::MaxClockSkew::BOUND_SECS + 1, -1] {
            let mut refused = args("server");
            refused.max_clock_skew = past;
            let mut ran = false;
            let got = refused.judge(|_| {
                ran = true;
                Ok(())
            });
            match got {
                Err(BindingError::Local(reason)) => assert!(
                    reason.contains(&mcp_re_core::MaxClockSkew::BOUND_SECS.to_string()),
                    "{reason}"
                ),
                other => panic!("{past}: expected a local refusal, got {other:?}"),
            }
            assert!(!ran, "{past}: no evidence is read under a refused skew");
        }
    }

    #[test]
    fn the_pinned_identity_is_refused_before_the_check_runs() {
        let mut ran = false;
        let got = args(" ").judge(|_| {
            ran = true;
            Ok(())
        });
        assert_eq!(
            got.err(),
            Some(BindingError::EmptyIssuerField(IssuerField::Role))
        );
        assert!(!ran, "no evidence is read under an empty pinned identity");
    }

    #[test]
    fn the_check_is_handed_the_callers_values_and_its_refusal_is_a_wire_code() {
        let seen = args("server")
            .judge(|j| Ok((j.response.status, j.request.target_uri.clone(), j.now)))
            .expect("the check runs");
        assert_eq!(seen, (200, "https://example.com/mcp".to_owned(), 1_000));
        let refused: Result<(), _> =
            args("server").judge(|_| Err(HttpProfileError::InvalidSignature));
        assert_eq!(
            refused.err(),
            Some(BindingError::Wire("mcp-re.invalid_signature"))
        );
    }
}
