// SPDX-License-Identifier: Apache-2.0
//! The verification arguments as the TypeScript API names them, grouped into what a verifier
//! is handed: the answer, the request it must bind to, the root issuer anchor, and the trust
//! policy the answer is judged under.

use mcp_re_binding_core::PinnedIssuer;
use mcp_re_binding_core::VerifyArgs;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;

use super::refusal::Refusal;
use super::to_pairs;
use super::whole_seconds;
use super::HttpHeader;

/// The response as it arrived.
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) headers: Vec<HttpHeader>,
    pub(crate) body: Vec<u8>,
}

/// The request this client transmitted, which the answer must bind to.
pub(crate) struct Transmitted {
    pub(crate) method: String,
    pub(crate) target_uri: String,
    pub(crate) headers: Vec<HttpHeader>,
    pub(crate) body: Vec<u8>,
}

/// The root issuer's identity values, as the caller supplied them.
pub(crate) struct Issuer {
    pub(crate) key_id: String,
    pub(crate) pubkey_b64url: String,
    pub(crate) role: String,
    pub(crate) trust_domain: String,
    pub(crate) subject: String,
    pub(crate) retired_until: Option<f64>,
}

/// The scope and currency the answer is judged under.
pub(crate) struct Trust {
    pub(crate) verifier_audiences: Vec<String>,
    pub(crate) expected_audience_hash: String,
    pub(crate) accepted_epochs: Vec<String>,
    pub(crate) max_clock_skew: f64,
    pub(crate) revoked_identifiers: Vec<String>,
    pub(crate) now: f64,
}

/// Everything a verification call names.
pub(crate) struct Verification {
    pub(crate) answer: Answer,
    pub(crate) transmitted: Transmitted,
    pub(crate) issuer: Issuer,
    pub(crate) trust: Trust,
}

impl Verification {
    /// The binding core's verification arguments, refusing a skew, time or retirement that
    /// is not whole in-range seconds.
    pub(crate) fn args(self) -> Result<VerifyArgs, Refusal> {
        let Self {
            answer,
            transmitted,
            issuer,
            trust,
        } = self;
        Ok(VerifyArgs {
            response: HttpResponse {
                status: answer.status,
                headers: to_pairs(answer.headers),
                body: answer.body,
            },
            request: HttpRequest {
                method: transmitted.method,
                target_uri: transmitted.target_uri,
                headers: to_pairs(transmitted.headers),
                body: transmitted.body,
            },
            issuer: issuer.pinned()?,
            verifier_audiences: trust.verifier_audiences,
            expected_audience_hash: trust.expected_audience_hash,
            accepted_epochs: trust.accepted_epochs,
            max_clock_skew: whole_seconds(trust.max_clock_skew, "maxClockSkew")?,
            revoked_identifiers: trust.revoked_identifiers,
            now: whole_seconds(trust.now, "now")?,
        })
    }
}

impl Issuer {
    fn pinned(self) -> Result<PinnedIssuer, Refusal> {
        Ok(PinnedIssuer {
            key_id: self.key_id,
            pubkey_b64url: self.pubkey_b64url,
            role: self.role,
            trust_domain: self.trust_domain,
            subject: self.subject,
            retired_until: self
                .retired_until
                .map(|t| whole_seconds(t, "issuerRetiredUntil"))
                .transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Answer;
    use super::Issuer;
    use super::Transmitted;
    use super::Trust;
    use super::Verification;

    fn verification(now: f64, retired_until: Option<f64>) -> Verification {
        Verification {
            answer: Answer {
                status: 202,
                headers: vec![],
                body: b"resp".to_vec(),
            },
            transmitted: Transmitted {
                method: "POST".into(),
                target_uri: "https://t".into(),
                headers: vec![],
                body: b"req".to_vec(),
            },
            issuer: Issuer {
                key_id: "k".into(),
                pubkey_b64url: "p".into(),
                role: "r".into(),
                trust_domain: "d".into(),
                subject: "s".into(),
                retired_until,
            },
            trust: Trust {
                verifier_audiences: vec!["v".into()],
                expected_audience_hash: "x".into(),
                accepted_epochs: vec!["e".into()],
                max_clock_skew: 5.0,
                revoked_identifiers: vec!["rv".into()],
                now,
            },
        }
    }

    #[test]
    fn each_verification_value_reaches_its_own_argument() {
        let Ok(args) = verification(7.0, Some(9.0)).args() else {
            panic!("whole seconds are not refused");
        };
        assert_eq!(args.response.status, 202);
        assert_eq!(args.response.body, b"resp");
        assert_eq!(args.request.body, b"req");
        assert_eq!(args.request.target_uri, "https://t");
        assert_eq!(args.expected_audience_hash, "x");
        assert_eq!((args.max_clock_skew, args.now), (5, 7));
        let issuer = args.issuer;
        assert_eq!(
            [
                issuer.key_id.as_str(),
                &issuer.pubkey_b64url,
                &issuer.role,
                &issuer.trust_domain,
                &issuer.subject
            ],
            ["k", "p", "r", "d", "s"]
        );
        assert_eq!(issuer.retired_until, Some(9));
    }

    #[test]
    fn a_time_that_is_not_whole_seconds_is_refused_by_name() {
        for (now, retired_until, named) in [
            (0.5, None, "now"),
            (7.0, Some(f64::INFINITY), "issuerRetiredUntil"),
        ] {
            let Err(refused) = verification(now, retired_until).args() else {
                panic!("{now}/{retired_until:?} must be refused");
            };
            assert!(refused.reason.starts_with(named), "{}", refused.reason);
        }
    }
}
