//! The non-owning view over an open session handle. The token operations the keysource
//! performs on a cached session are inherent methods added by the sibling modules
//! `find_objects`, `sign` and `ec_point`, and by `custody`.

use cryptoki_sys::CK_FUNCTION_LIST_PTR;
use cryptoki_sys::CK_SESSION_HANDLE;

use super::Pkcs11Context;

/// A NON-owning view over an already-open session handle. Does NOT close the handle on
/// drop — the handle's lifetime is owned elsewhere (the keysource's amortized session
/// cache). Obtained via [`Pkcs11Context::with_handle`]; borrows the context so it cannot
/// outlive the loaded module.
pub struct SessionRef<'ctx> {
    // `pub(super)`: the sibling modules that add operations to this view read these fields.
    pub(super) function_list: CK_FUNCTION_LIST_PTR,
    pub(super) handle: CK_SESSION_HANDLE,
    #[allow(dead_code)]
    _marker: std::marker::PhantomData<&'ctx Pkcs11Context>,
}

impl<'ctx> SessionRef<'ctx> {
    pub(super) fn new(function_list: CK_FUNCTION_LIST_PTR, handle: CK_SESSION_HANDLE) -> Self {
        SessionRef {
            function_list,
            handle,
            _marker: std::marker::PhantomData,
        }
    }
}
