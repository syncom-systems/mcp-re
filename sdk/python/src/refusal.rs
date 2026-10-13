// SPDX-License-Identifier: Apache-2.0
//! How a refusal crosses into Python: typed, never as prose to parse.
//!
//! [`WireRefusal`] carries the frozen `mcp-re.*` token in `.wire_code`;
//! [`SigningDeviceFailure`] says the device could not sign and has no wire code, with the
//! device's own exception as `__cause__`; any other refusal of the caller's arguments is a
//! plain `ValueError`. The device seam that produces the device's exception is here too.

use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

use mcp_re_binding_core::BindingError;
use mcp_re_binding_core::SignError;

use super::field_name;

pyo3::create_exception!(
    _core,
    WireRefusal,
    pyo3::exceptions::PyValueError,
    "A refusal carrying a frozen `mcp-re.*` wire code in `.wire_code`."
);

pyo3::create_exception!(
    _core,
    SigningDeviceFailure,
    pyo3::exceptions::PyValueError,
    "A signing device could not sign. A local condition with no wire code: nothing was \
     signed or sent. `__cause__` is what the device raised, when it raised."
);

/// A binding refusal as the exception the Python SDK raises.
pub(super) fn raise(e: BindingError) -> PyErr {
    let message = e.message(field_name);
    let Some(code) = e.wire_code() else {
        return pyo3::exceptions::PyValueError::new_err(message);
    };
    Python::attach(|py| {
        let err = WireRefusal::new_err(message);
        // A fresh exception instance accepts any attribute; were the write to fail, the
        // raised error would still be a `WireRefusal` whose message is the token.
        let _ = err.value(py).setattr("wire_code", code);
        err
    })
}

/// A failed device-signed call as the exception the Python SDK raises.
pub(super) fn raise_signing(e: SignError<PyErr>) -> PyErr {
    let failure = match e {
        SignError::Refused(refusal) => return raise(refusal),
        SignError::Device(failure) => failure,
    };
    Python::attach(|py| {
        let (message, cause) = failure.into_report(|cause| exception_text(py, cause));
        let err = SigningDeviceFailure::new_err(message);
        err.set_cause(py, cause);
        err
    })
}

/// What a device's exception says, or its type name when it says nothing.
fn exception_text(py: Python<'_>, e: &PyErr) -> String {
    let value = e.value(py);
    let said = value.str().map(|s| s.to_string()).unwrap_or_default();
    if !said.is_empty() {
        return said;
    }
    value
        .get_type()
        .name()
        .map(|n| n.to_string())
        .unwrap_or_default()
}

/// A device callback as the core's device seam: the signature bytes, or the device's own
/// exception when the callback raised or returned something that is not bytes.
pub(super) fn device<'a>(
    py: Python<'a>,
    sign_callback: &'a Py<PyAny>,
) -> impl FnOnce(&[u8]) -> PyResult<Vec<u8>> + 'a {
    move |preimage: &[u8]| {
        let out = sign_callback.call1(py, (PyBytes::new(py, preimage),))?;
        let out = out.bind(py);
        if let Ok(bytes) = out.cast::<PyBytes>() {
            return Ok(bytes.as_bytes().to_vec());
        }
        if let Ok(bytes) = out.cast::<PyByteArray>() {
            return Ok(bytes.to_vec());
        }
        let got = out
            .get_type()
            .name()
            .map(|n| n.to_string())
            .unwrap_or_default();
        Err(pyo3::exceptions::PyTypeError::new_err(not_bytes(&got)))
    }
}

/// The sentence for a device answer of Python type `type_name`, which is not bytes.
fn not_bytes(type_name: &str) -> String {
    format!("device returned {type_name}, expected bytes")
}

#[cfg(test)]
mod tests {
    use super::not_bytes;

    #[test]
    fn a_device_answer_that_is_not_bytes_is_named_by_its_python_type() {
        assert_eq!(not_bytes("str"), "device returned str, expected bytes");
    }
}
