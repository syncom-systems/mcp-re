//! The owning RAII session: login, hand-off of the raw handle, close on drop.

use cryptoki_sys::CKR_USER_ALREADY_LOGGED_IN;
use cryptoki_sys::CKU_USER;
use cryptoki_sys::CK_FUNCTION_LIST_PTR;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::check;
use super::Pkcs11Context;
use super::Pkcs11Error;

/// An open PKCS#11 session bound to a context's function list. Closes itself on
/// drop. Borrows the context so it cannot outlive the loaded module.
pub struct Session<'ctx> {
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    #[allow(dead_code)]
    _marker: std::marker::PhantomData<&'ctx Pkcs11Context>,
}

impl<'ctx> Session<'ctx> {
    pub(super) fn new(function_list: CK_FUNCTION_LIST_PTR, handle: CK_SESSION_HANDLE) -> Self {
        Session {
            function_list,
            handle,
            _marker: std::marker::PhantomData,
        }
    }

    /// Log in as the User with `pin`. The PIN bytes are passed straight to
    /// `C_Login` and are NOT copied or retained by this wrapper. Login state is per
    /// application per token, so a session opened after the first login is already
    /// authenticated: `CKR_USER_ALREADY_LOGGED_IN` is success, every other status fails.
    pub fn login_user(&self, pin: &str) -> Result<(), Pkcs11Error> {
        let pin_bytes = pin.as_bytes();
        // SAFETY: function-list non-null; `C_Login` checked non-null by `func!`.
        // PKCS#11 takes the PIN as a (ptr,len) pair; we pass the borrowed bytes
        // and their exact length. `C_Login` does not retain the pointer past the
        // call. The cast to *mut is required by the C signature but the module
        // treats the buffer as read-only.
        unsafe {
            let login = func!(self.function_list, C_Login);
            let rv = login(
                self.handle,
                CKU_USER,
                pin_bytes.as_ptr() as *mut u8,
                pin_bytes.len() as CK_ULONG,
            );
            if rv == CKR_USER_ALREADY_LOGGED_IN {
                return Ok(());
            }
            check(rv, "C_Login (CKU_USER)")
        }
    }

    /// Consume this session WITHOUT closing it, returning its raw
    /// `CK_SESSION_HANDLE`. The caller becomes responsible for the handle's
    /// lifetime (close it via a [`super::SessionCloser`]; `C_Finalize` on
    /// context drop is the backstop). Used by
    /// [`Pkcs11Context::open_logged_in_handle`] to hand out a cacheable handle.
    pub fn into_handle(self) -> CK_SESSION_HANDLE {
        let handle = self.handle;
        // SAFETY: forgetting suppresses this `Session`'s `Drop` (the
        // `C_CloseSession`), transferring ownership of `handle` to the caller. The
        // `Session` holds only `Copy` fields + a `PhantomData`, so there is no
        // owned resource leaked OTHER than the (now caller-owned) session handle;
        // the `_loader` library and function list live in `Pkcs11Context`, not here.
        std::mem::forget(self);
        handle
    }
}

impl<'ctx> Drop for Session<'ctx> {
    fn drop(&mut self) {
        if self.function_list.is_null() {
            return;
        }
        // SAFETY: `function_list` non-null (checked); if `C_CloseSession` is
        // present we call it once with this session's handle. A close error on
        // teardown has nowhere to go, so it is ignored — but we never call null.
        unsafe {
            if let Some(close) = (*self.function_list).C_CloseSession {
                let _ = close(self.handle);
            }
        }
    }
}
