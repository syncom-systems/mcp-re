//! `C_GetAttributeValue`: the `CKA_EC_POINT` of an object, and the sensitivity and
//! extractability flags of a private key.

use std::os::raw::c_ulong;
use std::ptr;

use cryptoki_sys::CKA_EC_POINT;
use cryptoki_sys::CKA_EXTRACTABLE;
use cryptoki_sys::CKA_SENSITIVE;
use cryptoki_sys::CKO_PRIVATE_KEY;
use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_BUFFER_TOO_SMALL;
use cryptoki_sys::CKR_OBJECT_HANDLE_INVALID;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::state::with_state;
use super::state::KeyObject;

pub(crate) unsafe extern "C" fn c_get_attribute_value(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: c_ulong,
) -> CK_RV {
    if templ.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(obj) = state.object(object) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        let attrs: &mut [CK_ATTRIBUTE] = std::slice::from_raw_parts_mut(templ, count as usize);
        for attr in attrs {
            let rv = fill(obj, attr);
            if rv != CKR_OK {
                return rv;
            }
        }
        CKR_OK
    })
}

/// Answer one template attribute for `obj`, in place.
unsafe fn fill(obj: &KeyObject, attr: &mut CK_ATTRIBUTE) -> CK_RV {
    let kind = attr.type_ as CK_ATTRIBUTE_TYPE;
    if let Some(flag) = private_key_flag(obj, kind) {
        if !attr.pValue.is_null() {
            *(attr.pValue as *mut u8) = u8::from(flag);
        }
        attr.ulValueLen = 1;
        return CKR_OK;
    }
    // Otherwise the client only ever asks for CKA_EC_POINT; anything else is
    // unsupported.
    if kind != CKA_EC_POINT {
        attr.ulValueLen = CK_ULONG::MAX; // CK_UNAVAILABLE_INFORMATION
        return CKR_OK;
    }
    write_value(&obj.ec_point, attr)
}

/// The value of `CKA_SENSITIVE` / `CKA_EXTRACTABLE`, reported for private objects only.
fn private_key_flag(obj: &KeyObject, kind: CK_ATTRIBUTE_TYPE) -> Option<bool> {
    if obj.class != CKO_PRIVATE_KEY {
        return None;
    }
    if kind == CKA_SENSITIVE {
        Some(!obj.exportable)
    } else if kind == CKA_EXTRACTABLE {
        Some(obj.exportable)
    } else {
        None
    }
}

/// Copy `value` into the attribute's buffer; a null buffer is the length query, a short
/// one is refused.
unsafe fn write_value(value: &[u8], attr: &mut CK_ATTRIBUTE) -> CK_RV {
    // Length-query call: report the length only.
    if attr.pValue.is_null() {
        attr.ulValueLen = value.len() as CK_ULONG;
        return CKR_OK;
    }
    if (attr.ulValueLen as usize) < value.len() {
        attr.ulValueLen = CK_ULONG::MAX;
        return CKR_BUFFER_TOO_SMALL;
    }
    ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len());
    attr.ulValueLen = value.len() as CK_ULONG;
    CKR_OK
}
