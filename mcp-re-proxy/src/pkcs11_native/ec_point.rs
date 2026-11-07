//! `CKA_EC_POINT` read over a session view, with the module-reported length bounded.

use std::ffi::c_void;
use std::ptr;

use cryptoki_sys::CKA_EC_POINT;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::check;
use super::Pkcs11Error;
use super::SessionRef;

/// Upper bound on a `CKA_EC_POINT` attribute length before allocation (same
/// ledger id). A DER-wrapped Edwards/EC point is tens of bytes (Ed25519 ≈ 34);
/// 4 KiB is far above any real curve while bounding the module-returned length.
const MAX_EC_POINT_LEN: usize = 4096;

impl SessionRef<'_> {
    /// Read the raw `CKA_EC_POINT` attribute of `key` via the two-call length idiom for
    /// `C_GetAttributeValue` (query length, allocate, fill).
    pub fn get_ec_point(&self, key: CK_OBJECT_HANDLE) -> Result<Vec<u8>, Pkcs11Error> {
        // First call: null pValue, learn ulValueLen.
        let mut probe = CK_ATTRIBUTE {
            type_: CKA_EC_POINT,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        };
        // SAFETY: function-list non-null; `C_GetAttributeValue` checked non-null by
        // `func!`. One-element attribute array; null pValue requests the length.
        unsafe {
            let get_attr = func!(self.function_list, C_GetAttributeValue);
            let rv = get_attr(self.handle, key, &mut probe, 1);
            check(rv, "C_GetAttributeValue (CKA_EC_POINT length)")?;
        }
        // ulValueLen == CK_UNAVAILABLE_INFORMATION (all-ones) signals the attribute
        // is absent / unreadable; an enormous length cannot be a 32-ish-byte point.
        let len = probe.ulValueLen;
        if len == CK_ULONG::MAX {
            return Err(Pkcs11Error::Protocol(
                "CKA_EC_POINT is unavailable on this object".to_string(),
            ));
        }
        // Bound the module-returned length before allocating (see MAX_EC_POINT_LEN).
        if len as usize > MAX_EC_POINT_LEN {
            return Err(Pkcs11Error::Protocol(format!(
                "CKA_EC_POINT reported an implausible length {len} (> {MAX_EC_POINT_LEN}); \
                 refusing to allocate"
            )));
        }

        let mut value: Vec<u8> = vec![0u8; len as usize];
        let mut fill = CK_ATTRIBUTE {
            type_: CKA_EC_POINT,
            pValue: value.as_mut_ptr() as *mut c_void,
            ulValueLen: len,
        };
        // SAFETY: `value` has capacity `len`; `fill.pValue` points at it with the
        // matching `ulValueLen`. `C_GetAttributeValue` writes at most `len` bytes
        // and sets the actual length back into `fill.ulValueLen`.
        unsafe {
            let get_attr = func!(self.function_list, C_GetAttributeValue);
            let rv = get_attr(self.handle, key, &mut fill, 1);
            check(rv, "C_GetAttributeValue (CKA_EC_POINT)")?;
        }
        let written = fill.ulValueLen as usize;
        if written > value.len() {
            return Err(Pkcs11Error::Protocol(format!(
                "CKA_EC_POINT reported {written} bytes into a {}-byte buffer",
                value.len()
            )));
        }
        value.truncate(written);
        Ok(value)
    }
}
