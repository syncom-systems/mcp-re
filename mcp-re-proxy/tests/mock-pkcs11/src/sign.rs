//! `C_SignInit` / `C_Sign`: pure Ed25519 (`CKM_EDDSA`) over the selected private key.

use std::os::raw::c_uchar;
use std::os::raw::c_ulong;
use std::ptr;

use cryptoki_sys::CKM_EDDSA;
use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_BUFFER_TOO_SMALL;
use cryptoki_sys::CKR_GENERAL_ERROR;
use cryptoki_sys::CKR_KEY_HANDLE_INVALID;
use cryptoki_sys::CKR_MECHANISM_INVALID;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CK_MECHANISM;
use cryptoki_sys::CK_MECHANISM_TYPE;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use ed25519_dalek::Signer;

use super::state::with_state;
use super::state::State;

pub(crate) unsafe extern "C" fn c_sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (*mechanism).mechanism as CK_MECHANISM_TYPE != CKM_EDDSA {
        return CKR_MECHANISM_INVALID;
    }
    with_state(|state| {
        // The key must exist and be signable.
        if !state.object(key).is_some_and(|o| o.signing.is_some()) {
            return CKR_KEY_HANDLE_INVALID;
        }
        let Some(sess) = state.sessions.get_mut(&session) else {
            return CKR_GENERAL_ERROR;
        };
        sess.sign_key = Some(key);
        CKR_OK
    })
}

/// The 64-byte signature of `msg` under the key `session` selected with `C_SignInit`.
fn sign_with_selected_key(
    state: &State,
    session: CK_SESSION_HANDLE,
    msg: &[u8],
) -> Result<[u8; 64], CK_RV> {
    let key = state
        .sessions
        .get(&session)
        .and_then(|sess| sess.sign_key)
        .ok_or(CKR_GENERAL_ERROR)?;
    let signing = state
        .object(key)
        .and_then(|obj| obj.signing.as_ref())
        .ok_or(CKR_KEY_HANDLE_INVALID)?;
    Ok(signing.sign(msg).to_bytes())
}

// The five parameters are the `CK_C_Sign` ABI; the function-list slot fixes them.
pub(crate) unsafe extern "C" fn c_sign(
    session: CK_SESSION_HANDLE,
    data: *mut c_uchar,
    data_len: c_ulong,
    signature: *mut c_uchar,
    signature_len: *mut c_ulong,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let msg: &[u8] = if data.is_null() || data_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data, data_len as usize)
        };
        match sign_with_selected_key(state, session, msg) {
            Ok(sig) => write_signature(&sig, signature, signature_len),
            Err(rv) => rv,
        }
    })
}

/// Hand `sig` to the caller: a null buffer is the length query, a short one is refused
/// with the length needed.
unsafe fn write_signature(
    sig: &[u8],
    signature: *mut c_uchar,
    signature_len: *mut c_ulong,
) -> CK_RV {
    // Length-query call: report the signature length only.
    if signature.is_null() {
        *signature_len = sig.len() as c_ulong;
        return CKR_OK;
    }
    if (*signature_len as usize) < sig.len() {
        *signature_len = sig.len() as c_ulong;
        return CKR_BUFFER_TOO_SMALL;
    }
    ptr::copy_nonoverlapping(sig.as_ptr(), signature, sig.len());
    *signature_len = sig.len() as c_ulong;
    CKR_OK
}
