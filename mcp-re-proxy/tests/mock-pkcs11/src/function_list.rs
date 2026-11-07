//! The Cryptoki function list: only the slots this mock implements are filled.

use std::sync::OnceLock;

use cryptoki_sys::CK_FUNCTION_LIST;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_VERSION;

use super::attributes::c_get_attribute_value;
use super::find::c_find_objects;
use super::find::c_find_objects_final;
use super::find::c_find_objects_init;
use super::session::c_close_session;
use super::session::c_finalize;
use super::session::c_get_slot_list;
use super::session::c_get_token_info;
use super::session::c_initialize;
use super::session::c_login;
use super::session::c_open_session;
use super::sign::c_sign;
use super::sign::c_sign_init;

/// Leaked, process-lifetime function list. `C_GetFunctionList` hands back its
/// address on every call.
pub(crate) fn function_list_ptr() -> *mut CK_FUNCTION_LIST {
    static LIST: OnceLock<usize> = OnceLock::new();
    let addr = *LIST.get_or_init(|| {
        // SAFETY: `CK_FUNCTION_LIST` is all `Option<fn>` (null == None) plus a
        // `CK_VERSION` (two bytes) — an all-zero bit pattern is a valid, fully-NULL
        // function list. We then fill in only the slots this mock implements.
        let mut list: CK_FUNCTION_LIST = unsafe { std::mem::zeroed() };
        list.version = CK_VERSION {
            major: 2,
            minor: 40,
        };
        list.C_Initialize = Some(c_initialize);
        list.C_Finalize = Some(c_finalize);
        list.C_GetFunctionList = Some(c_get_function_list);
        list.C_GetSlotList = Some(c_get_slot_list);
        list.C_GetTokenInfo = Some(c_get_token_info);
        list.C_OpenSession = Some(c_open_session);
        list.C_CloseSession = Some(c_close_session);
        list.C_Login = Some(c_login);
        list.C_FindObjectsInit = Some(c_find_objects_init);
        list.C_FindObjects = Some(c_find_objects);
        list.C_FindObjectsFinal = Some(c_find_objects_final);
        list.C_SignInit = Some(c_sign_init);
        list.C_Sign = Some(c_sign);
        list.C_GetAttributeValue = Some(c_get_attribute_value);
        Box::into_raw(Box::new(list)) as usize
    });
    addr as *mut CK_FUNCTION_LIST
}

/// Function-list slot variant of `C_GetFunctionList` (same behaviour).
unsafe extern "C" fn c_get_function_list(pp_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    crate::C_GetFunctionList(pp_list)
}
