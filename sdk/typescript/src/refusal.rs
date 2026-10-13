// SPDX-License-Identifier: Apache-2.0
//! How a refusal crosses into JavaScript: typed, never as prose to parse.
//!
//! A thrown error's `code` is the frozen `mcp-re.*` token for a wire refusal,
//! [`SIGNING_DEVICE_FAILURE`] when the signing device could not sign (with what the device
//! threw as its `cause`), and [`INVALID_ARG`] for any other refusal of the caller's
//! arguments. The device seam that produces the device's error is here too.

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::Function;
use napi_derive::napi;

use mcp_re_binding_core::BindingError;
use mcp_re_binding_core::SignError;

use super::field_name;

/// A refusal thrown into JavaScript: its `code` says which kind it is.
pub(super) type Refusal = napi::Error<String>;

/// The `code` of a refusal of the caller's arguments that no wire code describes.
pub(super) const INVALID_ARG: &str = "InvalidArg";

/// The `code` of a signing device that could not sign: a local condition with no wire
/// code, since nothing was signed or sent.
#[napi]
pub const SIGNING_DEVICE_FAILURE: &str = "SigningDeviceFailure";

/// A binding refusal as the error the TypeScript SDK throws.
pub(super) fn raise(e: BindingError) -> Refusal {
    let code = e.wire_code().unwrap_or(INVALID_ARG);
    napi::Error::new(code.to_owned(), e.message(field_name))
}

/// A failed device-signed call as the error the TypeScript SDK throws. What the device
/// threw becomes the error's `cause`; a non-Buffer answer is described instead.
pub(super) fn raise_signing(e: SignError<napi::Error>) -> Refusal {
    let failure = match e {
        SignError::Refused(refusal) => return raise(refusal),
        SignError::Device(failure) => failure,
    };
    let (message, device_error) = failure.into_report(|e| {
        if e.status == napi::Status::GenericFailure {
            e.reason.clone()
        } else {
            "device returned a value that is not a Buffer, expected a Buffer".to_owned()
        }
    });
    let mut err = napi::Error::new(SIGNING_DEVICE_FAILURE.to_owned(), message);
    if let Some(thrown) = device_error.filter(|e| e.status == napi::Status::GenericFailure) {
        err.set_cause(thrown);
    }
    err
}

/// A device callback as the core's device seam: the signature bytes, or the error the
/// call raised — what the callback threw, or the refusal of an answer that is not a Buffer.
pub(super) fn device<'a, 'scope: 'a>(
    sign_callback: &'a Function<'scope, Buffer, Buffer>,
) -> impl FnOnce(&[u8]) -> napi::Result<Vec<u8>> + 'a {
    move |preimage: &[u8]| {
        sign_callback
            .call(Buffer::from(preimage.to_vec()))
            .map(|out| out.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::raise;
    use super::INVALID_ARG;
    use mcp_re_binding_core::BindingError;

    #[test]
    fn a_refusal_is_thrown_with_its_kind_in_the_code() {
        let wire = raise(BindingError::Wire("mcp-re.invalid_signature"));
        assert_eq!(wire.status, "mcp-re.invalid_signature");
        assert_eq!(wire.reason, "mcp-re.invalid_signature");
        let local = raise(BindingError::Local("params must be a JSON object".into()));
        assert_eq!(local.status, INVALID_ARG);
        assert_eq!(local.reason, "params must be a JSON object");
    }
}
