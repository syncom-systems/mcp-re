//! Cryptoki lifecycle: initialization, slot and token info, sessions and login.

use std::os::raw::c_uchar;
use std::os::raw::c_ulong;
use std::os::raw::c_void;
use std::ptr;

use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_BUFFER_TOO_SMALL;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CKR_SLOT_ID_INVALID;
use cryptoki_sys::CKR_USER_ALREADY_LOGGED_IN;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CK_TOKEN_INFO;
use cryptoki_sys::CK_USER_TYPE;

use super::state::replace_state;
use super::state::with_state;
use super::state::Session;
use super::state::State;

/// The single slot id this mock exposes.
const SLOT_ID: CK_SLOT_ID = 0;

pub(crate) unsafe extern "C" fn c_initialize(_args: *mut c_void) -> CK_RV {
    replace_state(Some(State::from_env()));
    CKR_OK
}

pub(crate) unsafe extern "C" fn c_finalize(_reserved: *mut c_void) -> CK_RV {
    replace_state(None);
    CKR_OK
}

pub(crate) unsafe extern "C" fn c_get_slot_list(
    _token_present: c_uchar,
    slot_list: *mut CK_SLOT_ID,
    count: *mut c_ulong,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Length-query call: report we have one slot.
    if slot_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *slot_list = SLOT_ID;
    *count = 1;
    CKR_OK
}

pub(crate) unsafe extern "C" fn c_get_token_info(
    slot: CK_SLOT_ID,
    info: *mut CK_TOKEN_INFO,
) -> CK_RV {
    if slot != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        // Zero the whole struct, then write the space-padded 32-byte label (the client
        // trims trailing spaces). Other fields are irrelevant to the client.
        ptr::write_bytes(info as *mut u8, 0, std::mem::size_of::<CK_TOKEN_INFO>());
        let mut label = [b' '; 32];
        let bytes = state.token_label.as_bytes();
        let n = bytes.len().min(32);
        label[..n].copy_from_slice(&bytes[..n]);
        (*info).label = label;
        CKR_OK
    })
}

// The five parameters are the `CK_C_OpenSession` ABI; the function-list slot fixes them.
pub(crate) unsafe extern "C" fn c_open_session(
    slot: CK_SLOT_ID,
    _flags: c_ulong,
    _application: *mut c_void,
    _notify: cryptoki_sys::CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if slot != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let handle = state.next_session;
        state.next_session += 1;
        state.sessions.insert(
            handle,
            Session {
                find: None,
                sign_key: None,
            },
        );
        *session = handle;
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        state.sessions.remove(&session);
        if state.sessions.is_empty() {
            state.logged_in = false;
        }
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn c_login(
    _session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: *mut c_uchar,
    _pin_len: c_ulong,
) -> CK_RV {
    // The mock accepts any PIN, but models the token's login state: a login while
    // the application is already logged in is refused, as on a real token.
    with_state(|state| {
        if state.logged_in {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        state.logged_in = true;
        CKR_OK
    })
}
