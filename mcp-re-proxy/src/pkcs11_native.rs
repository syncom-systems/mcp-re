//! Minimal, owned safe wrapper over the raw `cryptoki-sys` FFI bindings (issue
//! #4034 supply-chain follow-up).
//!
//! # Why this exists
//! The high-level `cryptoki` crate transitively pulls the UNMAINTAINED `paste` crate
//! (RUSTSEC-2024-0436), which fails the supply-chain gate; `cryptoki-sys` carries only the
//! raw PKCS#11 bindings and depends solely on `libloading`. This module is the SMALL safe
//! surface [`crate::pkcs11_keysource`] needs over them: load+initialize a module, enumerate
//! token slots and read their labels, open an RW session, log in as the User, find objects by
//! template, sign with `CKM_EDDSA`, read `CKA_EC_POINT` and a key's [`custody`]. Nothing more.
//!
//! # Function-list dispatch
//! PKCS#11 modules reliably export only `C_GetFunctionList`; the individual
//! `C_*` symbols are NOT guaranteed to be exported. So this wrapper loads the
//! module with `cryptoki_sys::Pkcs11::new` (libloading), calls
//! `C_GetFunctionList` ONCE to obtain the `CK_FUNCTION_LIST`, and invokes EVERY
//! subsequent PKCS#11 call through that list's function pointers — checking each
//! pointer is `Some` and failing closed (never calling a null pointer) if not.
//!
//! # Fail-closed posture
//! Every `CK_RV != CKR_OK`, every null function pointer, and every load failure
//! becomes an [`Pkcs11Error`] with context. There is no panic, no `unwrap`/
//! `expect`/`assert` on any token or FFI path, and never a fabricated result.
//!
//! # RAII
//! [`Pkcs11Context`] calls `C_Finalize` on drop; [`Session`] calls `C_CloseSession` on drop.
//!
//! Compiled ONLY under the non-default `pkcs11_keysource` feature.
#![cfg(feature = "pkcs11_keysource")]

use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use crate::config_state::key_file_access::executable_path_violation;
use cryptoki_sys::Pkcs11 as RawLoader;
use cryptoki_sys::CKF_OS_LOCKING_OK;
use cryptoki_sys::CKF_RW_SESSION;
use cryptoki_sys::CKF_SERIAL_SESSION;
use cryptoki_sys::CK_C_INITIALIZE_ARGS;
use cryptoki_sys::CK_FUNCTION_LIST_PTR;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CK_TOKEN_INFO;
use cryptoki_sys::CK_ULONG;

/// Upper bound on the slot count `C_GetSlotList` reports before allocating for it — the
/// two-call length idiom, with the same faulty/hostile-module threat as the signature and
/// EC-point lengths bounded in [`SessionRef`].
const MAX_SLOTS: usize = 1024;

/// Pull a `Some` function pointer out of the function list or fail closed. The
/// function-list members are `Option<unsafe extern "C" fn(...)>`; a `None` means
/// the module did not provide that entry, so calling it would be a null deref.
macro_rules! func {
    ($list:expr, $field:ident) => {
        (*$list)
            .$field
            .ok_or_else(|| Pkcs11Error::MissingFunction(stringify!($field).to_string()))?
    };
}

// The children use `func!` and reach `Pkcs11Context`'s private fields; both are in scope
// for them because they are declared below the macro and inside this module.
mod closer;
pub mod custody;
mod ec_point;
mod error;
mod find_objects;
mod identity;
mod session;
mod session_ref;
mod sign;
mod template;

pub use closer::SessionCloser;
pub use error::Pkcs11Error;
pub use identity::TokenIdentity;
pub use session::Session;
pub use session_ref::SessionRef;
pub use template::AttributeTemplate;
pub use template::ObjectClass;

use error::check;
use identity::verify_selected_token;

/// A loaded + initialized PKCS#11 module. Owns the `libloading` library (kept
/// alive for the lifetime of every call through the function list) and the
/// `CK_FUNCTION_LIST` pointer the module handed back. Calls `C_Finalize` on drop.
pub struct Pkcs11Context {
    /// The raw libloading loader. Held ONLY to keep the dynamic library mapped;
    /// all PKCS#11 calls go through `function_list`, never through this loader's
    /// per-symbol entries (those are not reliably exported by every module).
    _loader: RawLoader,
    /// The module's function list — the dispatch table for every `C_*` call.
    function_list: CK_FUNCTION_LIST_PTR,
}

impl Pkcs11Context {
    /// Load the module at `module_path`, call `C_GetFunctionList`, then
    /// `C_Initialize` with `CKF_OS_LOCKING_OK` (let the module use OS locking for
    /// thread safety). Fails closed on any load / null-list / `CK_RV` error.
    pub fn load_and_initialize(module_path: &str) -> Result<Self, Pkcs11Error> {
        if let Some(why) = executable_path_violation(module_path) {
            return Err(Pkcs11Error::Load(format!(
                "--pkcs11-module {module_path} is refused: {why}"
            )));
        }
        // SAFETY: `RawLoader::new` is unsafe purely because it `dlopen`s an
        // arbitrary shared object and calls its initializers. Whoever may write
        // this path may run code in this process, so it is first held to
        // `executable_path_violation`'s floor: no group/world write bit on the
        // resolved file or on any directory above it.
        let loader = unsafe { RawLoader::new(module_path) }
            .map_err(|e| Pkcs11Error::Load(format!("load module '{module_path}': {e}")))?;

        let mut function_list: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: `C_GetFunctionList` is the one symbol PKCS#11 modules must
        // export; we pass a valid `*mut CK_FUNCTION_LIST_PTR` for it to fill. The
        // loader's `C_GetFunctionList` entry is checked for load error first.
        let get_list = loader.C_GetFunctionList.as_ref().map_err(|e| {
            Pkcs11Error::Load(format!(
                "module '{module_path}' does not export C_GetFunctionList: {e}"
            ))
        })?;
        // SAFETY: single FFI call; `&mut function_list` is a valid out-pointer.
        let rv = unsafe { get_list(&mut function_list) };
        check(rv, "C_GetFunctionList")?;
        if function_list.is_null() {
            return Err(Pkcs11Error::Load(format!(
                "module '{module_path}' returned a null CK_FUNCTION_LIST"
            )));
        }

        // C_Initialize with OS locking so the module may be used from multiple
        // threads (CKF_OS_LOCKING_OK == OsThreads in the high-level crate).
        // SAFETY: CK_C_INITIALIZE_ARGS is a plain C struct of nullable function
        // pointers + a flags word + a reserved pointer; an all-zero bit pattern is
        // its valid "no custom mutexes, no reserved" form, which is exactly what
        // we want before setting `flags`.
        let mut args: CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
        args.flags = CKF_OS_LOCKING_OK;
        // SAFETY: `function_list` is non-null (checked); `C_Initialize` is pulled
        // from it and checked non-null by `func!`. `&mut args` outlives the call.
        unsafe {
            let init = func!(function_list, C_Initialize);
            let rv = init(&mut args as *mut CK_C_INITIALIZE_ARGS as *mut c_void);
            check(rv, "C_Initialize")?;
        }

        Ok(Pkcs11Context {
            _loader: loader,
            function_list,
        })
    }

    /// Enumerate token slots and return `(slot_id, identity)` for each slot
    /// that has a token present, using the two-call length idiom for
    /// `C_GetSlotList` and reading each token's identity via
    /// [`Self::token_identity`].
    pub fn token_slots(&self) -> Result<Vec<(CK_SLOT_ID, TokenIdentity)>, Pkcs11Error> {
        // First call (null buffer) learns the count; second fills it.
        let mut count: CK_ULONG = 0;
        // SAFETY: function-list pointer non-null; `C_GetSlotList` checked non-null
        // by `func!`. token_present=1, null slot buffer, `&mut count` out-param.
        unsafe {
            let get_slots = func!(self.function_list, C_GetSlotList);
            let rv = get_slots(1, ptr::null_mut(), &mut count);
            check(rv, "C_GetSlotList (count)")?;
        }
        if count as usize > MAX_SLOTS {
            return Err(Pkcs11Error::Protocol(format!(
                "C_GetSlotList reported an implausible slot count {count} (> {MAX_SLOTS}); \
                 refusing to allocate"
            )));
        }
        let mut slots: Vec<CK_SLOT_ID> = vec![0; count as usize];
        // SAFETY: `slots` has capacity `count`; we pass its base pointer and the
        // SAME count we sized it to, and `C_GetSlotList` writes at most `count`.
        unsafe {
            let get_slots = func!(self.function_list, C_GetSlotList);
            let rv = get_slots(1, slots.as_mut_ptr(), &mut count);
            check(rv, "C_GetSlotList (fill)")?;
        }
        // The module may report fewer than the first count; honour the second.
        slots.truncate(count as usize);

        let mut out = Vec::with_capacity(slots.len());
        for slot in slots {
            out.push((slot, self.token_identity(slot)?));
        }
        Ok(out)
    }

    /// Read the identity of the token currently present in `slot` (one `C_GetTokenInfo`).
    pub fn token_identity(&self, slot: CK_SLOT_ID) -> Result<TokenIdentity, Pkcs11Error> {
        // SAFETY: CK_TOKEN_INFO is a plain C struct of fixed byte arrays and
        // integer words; an all-zero bit pattern is a valid (empty) value to
        // hand to C_GetTokenInfo, which overwrites it.
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: function-list pointer non-null; `C_GetTokenInfo` checked
        // non-null by `func!`; `&mut info` is a valid CK_TOKEN_INFO out-param.
        unsafe {
            let get_info = func!(self.function_list, C_GetTokenInfo);
            let rv = get_info(slot, &mut info);
            check(rv, "C_GetTokenInfo")?;
        }
        Ok(TokenIdentity::from_info(&info))
    }

    /// Open a serial RW session on `slot`. The returned [`Session`] closes itself
    /// on drop (`C_CloseSession`).
    pub fn open_rw_session(&self, slot: CK_SLOT_ID) -> Result<Session<'_>, Pkcs11Error> {
        let mut handle: CK_SESSION_HANDLE = 0;
        // SAFETY: function-list non-null; `C_OpenSession` checked non-null by
        // `func!`. PKCS#11 requires CKF_SERIAL_SESSION; we add CKF_RW_SESSION for
        // login + signing. No app pointer / notify callback; `&mut handle` filled.
        unsafe {
            let open = func!(self.function_list, C_OpenSession);
            let rv = open(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            );
            check(rv, "C_OpenSession")?;
        }
        Ok(Session::new(self.function_list, handle))
    }

    /// Open an RW session on `slot` and log in as the User with `pin`, returning
    /// the raw `CK_SESSION_HANDLE` WITHOUT closing it — the caller becomes
    /// responsible for that handle's lifetime (close it with a
    /// [`SessionCloser`]; [`Pkcs11Context`]'s `C_Finalize` on drop is the
    /// backstop). This is the ONE login that the keysource's session amortization
    /// (audit M16) eliminates per-operation: the handle is cached and reused.
    ///
    /// The token present in `slot` must still be `expected` when the session is open
    /// and before `C_Login`, so a token swapped in after selection never receives the
    /// PIN.
    ///
    /// Implemented by opening a normal RAII [`Session`], verifying the token, logging
    /// in, then [`Session::into_handle`]-ing it so the `Drop` close is suppressed.
    pub fn open_logged_in_handle(
        &self,
        slot: CK_SLOT_ID,
        expected: &TokenIdentity,
        pin: &str,
    ) -> Result<CK_SESSION_HANDLE, Pkcs11Error> {
        let session = self.open_rw_session(slot)?;
        verify_selected_token(slot, expected, self.token_identity(slot)?)?;
        session.login_user(pin)?;
        Ok(session.into_handle())
    }

    /// Borrow a NON-owning view over an already-open session `handle` (typically
    /// one from [`Self::open_logged_in_handle`]). [`SessionRef`] carries the
    /// `find_objects` / `sign_eddsa` / `get_ec_point` operations and does NOT close
    /// the handle on drop — the caller owns the handle's lifetime. The returned view
    /// borrows `self`, so it cannot outlive the loaded module.
    pub fn with_handle(&self, handle: CK_SESSION_HANDLE) -> SessionRef<'_> {
        SessionRef::new(self.function_list, handle)
    }

    /// A lifetime-free closer for this context's sessions. It holds an `Arc` of the
    /// context, so a caller can store it next to a cached raw `CK_SESSION_HANDLE` and
    /// close that handle on retirement WITHOUT a borrow of the context — the keysource
    /// uses this to make its handle cache an RAII type while sidestepping the
    /// self-referential `Session<'ctx>` lifetime. The held `Arc` keeps the module
    /// un-finalized for as long as any closer exists.
    pub fn session_closer(self: &Arc<Self>) -> SessionCloser {
        SessionCloser::new(Arc::clone(self))
    }
}

impl Drop for Pkcs11Context {
    fn drop(&mut self) {
        if self.function_list.is_null() {
            return;
        }
        // SAFETY: `function_list` non-null (checked); if `C_Finalize` is present
        // we call it once with the spec-mandated null reserved arg. A finalize
        // error on teardown has nowhere meaningful to go, so it is ignored — but
        // we never call a null pointer.
        unsafe {
            if let Some(finalize) = (*self.function_list).C_Finalize {
                let _ = finalize(ptr::null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NEGATIVE test for the module-path floor, AT THE CALL SITE that dlopens: a
    /// module file anyone may overwrite is refused BEFORE `RawLoader::new` maps it and
    /// runs its initializers. Removing the `executable_path_violation` guard from
    /// `load_and_initialize` turns this red — the call would then reach the loader and
    /// fail with a libloading message instead of a refusal.
    #[cfg(unix)]
    #[test]
    fn a_world_writable_module_is_refused_before_it_is_loaded() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp-re-pkcs11-w-{}", std::process::id()));
        std::fs::write(&path, b"not really a module").expect("write module");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("chmod 0666");
        let error = Pkcs11Context::load_and_initialize(path.to_str().expect("utf-8"))
            .err()
            .expect("a world-writable module must not be loaded");
        let rendered = format!("{error}");
        assert!(
            rendered.contains("is refused") && rendered.contains("group/world-writable"),
            "expected the executable-path floor to refuse it, got: {rendered}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The POSITIVE control for that guard, and the one that decides whether the floor is
    /// deployable: an ordinary system path under root-owned `0755` directories — the
    /// posture of `/usr/lib/softhsm/libsofthsm2.so` — must PASS the floor and reach the
    /// loader. It is not a Cryptoki module, so it still fails; what this asserts is that
    /// it failed at the LOADER and not at the floor.
    #[cfg(unix)]
    #[test]
    fn an_ordinary_system_path_passes_the_floor_and_reaches_the_loader() {
        let system_file = ["/bin/sh", "/bin/ls", "/usr/bin/env"]
            .into_iter()
            .find(|p| std::fs::metadata(p).is_ok())
            .expect("a POSIX host exposes at least one of /bin/sh, /bin/ls, /usr/bin/env");
        let error = Pkcs11Context::load_and_initialize(system_file)
            .err()
            .unwrap_or_else(|| panic!("{system_file} is not a Cryptoki module"));
        let rendered = format!("{error}");
        assert!(
            !rendered.contains("is refused"),
            "a root-owned file under 0755 directories must not be refused by the floor, \
             or no packaged PKCS#11 module would load: {rendered}"
        );
    }
}
