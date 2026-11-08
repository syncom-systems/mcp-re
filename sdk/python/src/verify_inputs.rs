// SPDX-License-Identifier: Apache-2.0
//! The verification arguments as the Python API names them, grouped into what a verifier is
//! handed: the answer, the request it must bind to, the root issuer anchor, and the trust
//! policy the answer is judged under.

use mcp_re_binding_core::PinnedIssuer;
use mcp_re_binding_core::VerifyArgs;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;

/// The response as it arrived.
pub(crate) struct Answer<'a> {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: &'a [u8],
}

/// The request this client transmitted, which the answer must bind to.
pub(crate) struct Transmitted<'a> {
    pub(crate) method: &'a str,
    pub(crate) target_uri: &'a str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: &'a [u8],
}

/// The root issuer's identity values, as the caller supplied them.
pub(crate) struct Issuer<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) pubkey_b64url: &'a str,
    pub(crate) role: &'a str,
    pub(crate) trust_domain: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) retired_until: Option<i64>,
}

/// The scope and currency the answer is judged under.
pub(crate) struct Trust<'a> {
    pub(crate) verifier_audiences: Vec<String>,
    pub(crate) expected_audience_hash: &'a str,
    pub(crate) accepted_epochs: Vec<String>,
    pub(crate) max_clock_skew: i64,
    pub(crate) revoked_identifiers: Vec<String>,
    pub(crate) now: i64,
}

/// Everything a verification call names.
pub(crate) struct Verification<'a> {
    pub(crate) answer: Answer<'a>,
    pub(crate) transmitted: Transmitted<'a>,
    pub(crate) issuer: Issuer<'a>,
    pub(crate) trust: Trust<'a>,
}

impl Verification<'_> {
    /// The binding core's verification arguments.
    pub(crate) fn args(self) -> VerifyArgs {
        let Self {
            answer,
            transmitted,
            issuer,
            trust,
        } = self;
        VerifyArgs {
            response: HttpResponse {
                status: answer.status,
                headers: answer.headers,
                body: answer.body.to_vec(),
            },
            request: HttpRequest {
                method: transmitted.method.to_owned(),
                target_uri: transmitted.target_uri.to_owned(),
                headers: transmitted.headers,
                body: transmitted.body.to_vec(),
            },
            issuer: issuer.pinned(),
            verifier_audiences: trust.verifier_audiences,
            expected_audience_hash: trust.expected_audience_hash.to_owned(),
            accepted_epochs: trust.accepted_epochs,
            max_clock_skew: trust.max_clock_skew,
            revoked_identifiers: trust.revoked_identifiers,
            now: trust.now,
        }
    }
}

impl Issuer<'_> {
    fn pinned(self) -> PinnedIssuer {
        PinnedIssuer {
            key_id: self.key_id.to_owned(),
            pubkey_b64url: self.pubkey_b64url.to_owned(),
            role: self.role.to_owned(),
            trust_domain: self.trust_domain.to_owned(),
            subject: self.subject.to_owned(),
            retired_until: self.retired_until,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Answer;
    use super::Issuer;
    use super::Transmitted;
    use super::Trust;
    use super::Verification;

    #[test]
    fn each_verification_value_reaches_its_own_argument() {
        let args = Verification {
            answer: Answer {
                status: 202,
                headers: vec![("h".into(), "1".into())],
                body: b"resp",
            },
            transmitted: Transmitted {
                method: "POST",
                target_uri: "https://t",
                headers: vec![("q".into(), "2".into())],
                body: b"req",
            },
            issuer: Issuer {
                key_id: "k",
                pubkey_b64url: "p",
                role: "r",
                trust_domain: "d",
                subject: "s",
                retired_until: Some(9),
            },
            trust: Trust {
                verifier_audiences: vec!["v".into()],
                expected_audience_hash: "x",
                accepted_epochs: vec!["e".into()],
                max_clock_skew: 5,
                revoked_identifiers: vec!["rv".into()],
                now: 7,
            },
        }
        .args();
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
}
