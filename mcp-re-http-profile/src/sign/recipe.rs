// SPDX-License-Identifier: Apache-2.0
//! What every signature this profile emits has in common: the parameters it states, the
//! components a response covers, and the body digest the signer authors.

use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::ids::ALG_ED25519;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::message::reject_content_encoding;
use crate::message::HttpResponse;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;

use super::set_header;

/// The RFC 9421 parameters every signature this profile emits states: algorithm and
/// profile tag are the profile's, the rest is the signer's. A response carries no nonce; a
/// request does.
pub(crate) fn profile_params(
    key_id: &str,
    created: i64,
    expires: i64,
    nonce: Option<&str>,
) -> SignatureParams {
    SignatureParams {
        created: Some(created),
        expires: Some(expires),
        nonce: nonce.map(str::to_owned),
        keyid: Some(key_id.to_owned()),
        alg: Some(ALG_ED25519.to_owned()),
        tag: Some(PROFILE_TAG.to_owned()),
    }
}

/// The RFC 9421 parameters one response signature states: who signs, and when the
/// signature was created and stops being valid. The response-side counterpart of
/// [`RequestSignature`](super::RequestSignature); a response carries no nonce.
#[derive(Debug, Clone, Copy)]
pub struct ResponseSignature<'a> {
    pub key_id: &'a str,
    pub created: i64,
    pub expires: i64,
}

impl ResponseSignature<'_> {
    pub(crate) fn params(&self) -> SignatureParams {
        profile_params(self.key_id, self.created, self.expires, None)
    }
}

/// The components a full response signature covers: the response's own, and, when the
/// response is bound to a request, that request's under `;req`.
pub(super) fn response_components(bound: bool) -> Vec<CoveredComponent> {
    let mut components: Vec<CoveredComponent> = REQUIRED_RESPONSE_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    if bound {
        components.extend(
            REQUIRED_RESPONSE_REQ_COMPONENTS
                .iter()
                .map(|n| CoveredComponent::req(n)),
        );
    }
    components
}

/// Refuse a response that already declares a content coding, then state the digest of the
/// body actually carried; the signer is the sole author of `Content-Digest`.
pub(super) fn seal_response_body(response: &mut HttpResponse) -> Result<(), HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    set_header(
        &mut response.headers,
        "Content-Digest",
        content_digest_sha256(&response.body),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_states_its_nonce_and_a_response_none() {
        let request = profile_params("k", 1, 2, Some("n"));
        let response = profile_params("k", 1, 2, None);
        assert_eq!(request.nonce.as_deref(), Some("n"));
        assert_eq!(response.nonce, None);
        assert_eq!(request.alg.as_deref(), Some(ALG_ED25519));
        assert_eq!(request.tag.as_deref(), Some(PROFILE_TAG));
    }

    #[test]
    fn only_a_bound_response_covers_request_components() {
        let unbound = response_components(false);
        let bound = response_components(true);
        assert_eq!(unbound.len(), REQUIRED_RESPONSE_COMPONENTS.len());
        assert_eq!(
            bound.len(),
            REQUIRED_RESPONSE_COMPONENTS.len() + REQUIRED_RESPONSE_REQ_COMPONENTS.len()
        );
    }

    fn response(headers: Vec<(String, String)>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers,
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn sealing_states_the_digest_of_the_body_carried() {
        let mut r = response(vec![("Content-Digest".into(), "sha-256=:stale:".into())]);
        seal_response_body(&mut r).expect("no content coding");
        let digests: Vec<_> = r
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-digest"))
            .collect();
        assert_eq!(
            digests.len(),
            1,
            "the signer is the sole author of the digest"
        );
        assert_eq!(digests[0].1, content_digest_sha256(b"{}"));
    }

    #[test]
    fn a_response_already_declaring_a_content_coding_is_not_sealed() {
        let mut r = response(vec![("Content-Encoding".into(), "gzip".into())]);
        assert_eq!(
            seal_response_body(&mut r),
            Err(HttpProfileError::ContentEncodingPresent)
        );
        assert!(
            !r.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("content-digest")),
            "a refused response carries no digest"
        );
    }
}
