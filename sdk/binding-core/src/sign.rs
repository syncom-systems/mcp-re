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
use crate::DeviceFailure;
use crate::SignArgs;
use crate::SignError;

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
/// `device` returns the detached signature, or the host's own error when the call failed
/// or answered something that is not bytes. A device failure is reported as
/// [`SignError::Device`], never as a wire code: nothing was signed and nothing was sent,
/// so `mcp-re.invalid_signature` would claim a peer rejected a signature that never
/// existed. Fails closed either way: no unsigned or malformed evidence is emitted.
///
/// An answer of the wrong length is refused by the HTTP profile's signer seam, the one
/// place that length is checked. On this path the device's answer is the only signature
/// the seam can refuse, so a refusal that follows an answer is that answer's
/// [`DeviceFailure::Malformed`].
pub fn sign_with_device<E>(
    args: SignArgs,
    device: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<SignedParts, SignError<E>> {
    let m = args.read()?;
    let mut failed: Option<E> = None;
    let mut answered: Option<usize> = None;
    let sign_base = |preimage: &[u8]| match device(preimage) {
        Ok(signature) => {
            answered = Some(signature.len());
            Ok(signature)
        }
        Err(e) => {
            failed = Some(e);
            Err(HttpProfileError::InvalidSignature)
        }
    };
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
    };
    match (signed, failed, answered) {
        (Ok(signed), _, _) => Ok(SignedParts::from(signed)),
        (Err(_), Some(e), _) => Err(SignError::Device(DeviceFailure::Failed(e))),
        (Err(HttpProfileError::InvalidSignature), None, Some(octets)) => {
            Err(SignError::Device(DeviceFailure::Malformed(octets)))
        }
        (Err(e), None, _) => Err(SignError::Refused(BindingError::from(e))),
    }
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
    use crate::DeviceFailure;
    use crate::SignArgs;
    use crate::SignError;

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
            let device = sign_with_device(args(call), |pre| sign_preimage(&SEED, pre))
                .expect("a device signs");
            assert_eq!(software, device);
            assert!(software
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("signature")));
        }
    }

    #[test]
    fn a_device_that_fails_is_a_device_failure_carrying_the_host_error() {
        for call in [request(), Call::Notification] {
            let got = sign_with_device(args(call), |_| Err::<Vec<u8>, _>("HSM unavailable"));
            assert!(
                matches!(
                    got,
                    Err(SignError::Device(DeviceFailure::Failed("HSM unavailable")))
                ),
                "{got:?}"
            );
        }
    }

    #[test]
    fn a_device_answer_that_is_not_64_octets_is_a_malformed_device_answer() {
        for octets in [0usize, 63, 65] {
            let got = sign_with_device(args(request()), |_| Ok::<_, ()>(vec![0u8; octets]));
            match got {
                Err(SignError::Device(DeviceFailure::Malformed(n))) => assert_eq!(n, octets),
                other => panic!("{octets}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_refusal_the_device_did_not_cause_is_not_blamed_on_it() {
        let mut bad = args(request());
        bad.params_json = r#""not-an-object""#.into();
        let got = sign_with_device(bad, |_| -> Result<Vec<u8>, ()> {
            panic!("the device is not consulted for a refused call")
        });
        assert!(
            matches!(&got, Err(SignError::Refused(BindingError::Local(reason))) if reason == "params must be a JSON object"),
            "{got:?}"
        );
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
