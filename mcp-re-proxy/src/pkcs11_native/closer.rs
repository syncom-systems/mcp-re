//! A lifetime-free capability to close a context's sessions.

use std::sync::Arc;

use cryptoki_sys::CK_SESSION_HANDLE;

use super::check;
use super::Pkcs11Context;
use super::Pkcs11Error;

/// A lifetime-free handle to a context's `C_CloseSession` that keeps the context alive.
/// See [`Pkcs11Context::session_closer`].
#[derive(Clone)]
pub struct SessionCloser {
    context: Arc<Pkcs11Context>,
}

impl SessionCloser {
    pub(super) fn new(context: Arc<Pkcs11Context>) -> Self {
        Self { context }
    }

    /// Close `handle`. Fails closed on a non-`CKR_OK` status or a missing
    /// `C_CloseSession` entry (never a null call).
    pub fn close(&self, handle: CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
        let function_list = self.context.function_list;
        if function_list.is_null() {
            return Err(Pkcs11Error::Load(
                "session closer has a null function list".to_string(),
            ));
        }
        // SAFETY: function-list non-null (checked); `C_CloseSession` checked
        // non-null by `func!`. It takes only the session handle. The held
        // `Arc<Pkcs11Context>` keeps the context un-finalized, so the function list
        // is still live.
        unsafe {
            let close = func!(function_list, C_CloseSession);
            check(close(handle), "C_CloseSession")
        }
    }
}
