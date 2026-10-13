// SPDX-License-Identifier: Apache-2.0
//! What a non-exporting signing operation can fail with: a refusal of the call, or a
//! device that could not sign.

use crate::BindingError;

/// The length of a detached Ed25519 signature (RFC 8032), as a device failure names it.
/// The HTTP profile's signer seam is what enforces it.
const ED25519_SIGNATURE_OCTETS: usize = 64;

/// Why a host signing device produced no usable signature.
///
/// A local condition: nothing was signed and nothing was sent, so no `mcp-re.*` wire code
/// describes it. `E` is the host's own error value, carried so a binding can raise the
/// device failure with that value as its cause.
#[derive(Debug)]
pub enum DeviceFailure<E> {
    /// The host call failed, or answered something that is not bytes.
    Failed(E),
    /// The device answered this many octets, which is not an Ed25519 signature.
    Malformed(usize),
}

impl<E> DeviceFailure<E> {
    /// The sentence a binding raises, and the host error to raise it from when the device
    /// itself failed. `describe` words a failed call in the host's own terms.
    pub fn into_report(self, describe: impl FnOnce(&E) -> String) -> (String, Option<E>) {
        match self {
            DeviceFailure::Failed(e) => (describe(&e), Some(e)),
            DeviceFailure::Malformed(octets) => (
                format!(
                    "device returned a {octets}-byte signature, expected {ED25519_SIGNATURE_OCTETS}"
                ),
                None,
            ),
        }
    }
}

/// Why a device-signed call failed.
#[derive(Debug)]
pub enum SignError<E> {
    /// The call was refused before or after the device was consulted, for a reason the
    /// device did not cause.
    Refused(BindingError),
    /// The device could not sign.
    Device(DeviceFailure<E>),
}

impl<E> From<BindingError> for SignError<E> {
    fn from(e: BindingError) -> Self {
        SignError::Refused(e)
    }
}

#[cfg(test)]
mod tests {
    use super::DeviceFailure;

    #[test]
    fn a_malformed_answer_names_its_length_and_a_failed_call_is_worded_by_the_host() {
        assert_eq!(
            DeviceFailure::<&str>::Malformed(63).into_report(|e| (*e).to_owned()),
            (
                "device returned a 63-byte signature, expected 64".to_owned(),
                None
            )
        );
        assert_eq!(
            DeviceFailure::Failed("HSM unavailable").into_report(|e| format!("host: {e}")),
            ("host: HSM unavailable".to_owned(), Some("HSM unavailable"))
        );
    }
}
