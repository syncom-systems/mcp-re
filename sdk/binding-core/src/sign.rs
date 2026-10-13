// SPDX-License-Identifier: Apache-2.0
//! Signing, under both custody classes (ADR-MCPS-044 §Compliance).
//!
//! Software custody takes a raw 32-byte seed. Non-exporting custody takes only a device: a
//! host callback that receives the exact signature-base bytes and returns a detached
//! Ed25519 signature, so the private key never enters the SDK. The evidence is
//! byte-identical either way; only where the key lives differs.

use mcp_re_client_core::build_signed_notification;
use mcp_re_client_core::build_signed_notification_with_signer;
use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::SignedRequest;
use mcp_re_core::SigningKey;

use crate::BindingError;
use crate::SignArgs;

/// A signed RFC 9421 message as plain values: the HTTP method, `@target-uri`, headers
/// (carrying `Signature`, `Signature-Input` and `Content-Digest`) and body, plus the request
/// evidence handle that binds a later signed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedParts {
    pub method: String,
    pub target_uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub evidence_digest_alg: String,
    pub evidence_digest_value: String,
}

impl From<SignedRequest> for SignedParts {
    fn from(signed: SignedRequest) -> Self {
        let req = signed.request();
        SignedParts {
            method: req.method.clone(),
            target_uri: req.target_uri.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            evidence_digest_alg: signed.evidence().digest_alg().to_owned(),
            evidence_digest_value: signed.evidence().digest_value().to_owned(),
        }
    }
}

/// Sign with a raw seed (software custody).
pub fn sign(args: SignArgs, seed: &[u8]) -> Result<SignedParts, BindingError> {
    let key = seed_to_key(seed)?;
    let m = args.read()?;
    let signed = match &m.id {
        Some(id) => build_signed_request(id, &m.method, m.params, &m.target_uri, &m.inputs, &key),
        None => build_signed_notification(&m.method, m.params, &m.target_uri, &m.inputs, &key),
    }?;
    Ok(SignedParts::from(signed))
}

/// Sign through a device (non-exporting custody).
///
/// `device` returns the signature, or `None` when the host call failed or returned
/// something that is not bytes. Either is an unusable signature, and so is an answer that
/// is not 64 octets, which the HTTP profile's signer seam refuses: the call fails closed as
/// `mcp-re.invalid_signature` rather than emitting unsigned or malformed evidence.
pub fn sign_with_device(
    args: SignArgs,
    device: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Result<SignedParts, BindingError> {
    let m = args.read()?;
    let sign_base = |preimage: &[u8]| device(preimage).ok_or(HttpProfileError::InvalidSignature);
    let signed = match &m.id {
        Some(id) => build_signed_request_with_signer(
            id,
            &m.method,
            m.params,
            &m.target_uri,
            &m.inputs,
            sign_base,
        ),
        None => build_signed_notification_with_signer(
            &m.method,
            m.params,
            &m.target_uri,
            &m.inputs,
            sign_base,
        ),
    }?;
    Ok(SignedParts::from(signed))
}

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature: the primitive a host-side signing device is built on, and the operation the
/// software path performs internally, so a device signature is byte-identical to it.
pub fn sign_preimage(seed: &[u8], preimage: &[u8]) -> Result<Vec<u8>, BindingError> {
    let key = seed_to_key(seed)?;
    mcp_re_core::b64url_decode(&key.sign(preimage))
        .map_err(|_| BindingError::from(HttpProfileError::InvalidSignature))
}

fn seed_to_key(seed: &[u8]) -> Result<SigningKey, BindingError> {
    let seed: &[u8; 32] = seed
        .try_into()
        .map_err(|_| BindingError::Local("signing seed must be exactly 32 bytes".into()))?;
    Ok(SigningKey::from_seed_bytes(seed))
}

#[cfg(test)]
mod tests {
    use super::sign;
    use super::sign_preimage;
    use super::sign_with_device;
    use crate::BindingError;
    use crate::Call;
    use crate::ContinuationArgs;
    use crate::SignArgs;

    const SEED: [u8; 32] = [7u8; 32];

    fn args(call: Call) -> SignArgs {
        SignArgs {
            call,
            key_id: "client-1".into(),
            method: "tools/call".into(),
            params_json: r#"{"name":"echo"}"#.into(),
            target_uri: "https://example.com/mcp".into(),
            audience_id: "aud".into(),
            route: None,
            dpop_token: "tok".into(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            created: 1_000,
            expires: 1_060,
            bindings_json: None,
        }
    }

    fn request() -> Call {
        Call::Request {
            id_json: "1".into(),
            continuation: ContinuationArgs::default(),
        }
    }

    #[test]
    fn a_device_signature_is_byte_identical_to_the_software_one() {
        for call in [request(), Call::Notification] {
            let software = sign(args(call.clone()), &SEED).expect("software signs");
            let device = sign_with_device(args(call), |pre| sign_preimage(&SEED, pre).ok())
                .expect("a device signs");
            assert_eq!(software, device);
            assert!(software
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("signature")));
        }
    }

    #[test]
    fn a_device_that_fails_or_answers_anything_but_64_octets_fails_closed() {
        for answer in [
            None,
            Some(vec![0u8; 63]),
            Some(vec![0u8; 65]),
            Some(Vec::new()),
        ] {
            let got = sign_with_device(args(request()), |_| answer.clone());
            assert_eq!(
                got.err(),
                Some(BindingError::Wire("mcp-re.invalid_signature")),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn a_seed_that_is_not_32_bytes_is_refused() {
        for seed in [&[0u8; 31][..], &[0u8; 33][..], &[][..]] {
            let expected = Some(BindingError::Local(
                "signing seed must be exactly 32 bytes".into(),
            ));
            assert_eq!(sign(args(request()), seed).err(), expected);
            assert_eq!(sign_preimage(seed, b"x").err(), expected);
        }
    }
}
