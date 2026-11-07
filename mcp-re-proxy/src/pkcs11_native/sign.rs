//! `CKM_EDDSA` signing over a session view, with the module-reported length bounded.

use std::ptr;

use cryptoki_sys::CKM_EDDSA;
use cryptoki_sys::CK_MECHANISM;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::check;
use super::Pkcs11Error;
use super::SessionRef;

/// Upper bound on a `C_Sign`-reported signature length before we allocate a
/// buffer for it (audit LOW, ledger `8af4c26be9bccb3e`). This module only ever
/// signs with `CKM_EDDSA` (Ed25519 → 64 bytes); 256 is a generous ceiling that
/// still covers any Edwards variant while refusing an outsized allocation a
/// faulty/hostile module could request via the two-call length idiom.
const MAX_SIGNATURE_LEN: usize = 256;

impl SessionRef<'_> {
    /// Sign `data` under `key` with `CKM_EDDSA` (no pre-hash), returning the raw
    /// signature bytes via the two-call length idiom for `C_Sign`.
    pub fn sign_eddsa(&self, key: CK_OBJECT_HANDLE, data: &[u8]) -> Result<Vec<u8>, Pkcs11Error> {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        // SAFETY: function-list non-null; `C_SignInit` checked non-null by `func!`.
        // `&mut mechanism` is a valid CK_MECHANISM for the call; `key` is a handle.
        unsafe {
            let sign_init = func!(self.function_list, C_SignInit);
            let rv = sign_init(self.handle, &mut mechanism, key);
            check(rv, "C_SignInit (CKM_EDDSA)")?;
        }

        // First C_Sign (null signature buffer) learns the signature length.
        let mut sig_len: CK_ULONG = 0;
        // SAFETY: function-list non-null; `C_Sign` checked non-null by `func!`.
        // data ptr+len describe the borrowed preimage; null out-buffer + `&mut
        // sig_len` requests the length only (standard PKCS#11 length query).
        unsafe {
            let sign = func!(self.function_list, C_Sign);
            let rv = sign(
                self.handle,
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut sig_len,
            );
            check(rv, "C_Sign (length query)")?;
        }

        // Bound the module-returned length before allocating (see MAX_SIGNATURE_LEN).
        if sig_len as usize > MAX_SIGNATURE_LEN {
            return Err(Pkcs11Error::Protocol(format!(
                "C_Sign reported an implausible signature length {sig_len} (> {MAX_SIGNATURE_LEN}); \
                 refusing to allocate"
            )));
        }
        let mut signature: Vec<u8> = vec![0u8; sig_len as usize];
        // SAFETY: `signature` has capacity `sig_len`; we pass its pointer and the
        // SAME `sig_len`, which `C_Sign` may shrink (it writes the final length
        // back). data ptr+len unchanged from the query call.
        unsafe {
            let sign = func!(self.function_list, C_Sign);
            let rv = sign(
                self.handle,
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &mut sig_len,
            );
            check(rv, "C_Sign")?;
        }
        let written = sig_len as usize;
        if written > signature.len() {
            return Err(Pkcs11Error::Protocol(format!(
                "C_Sign reported {written} bytes into a {}-byte buffer",
                signature.len()
            )));
        }
        signature.truncate(written);
        Ok(signature)
    }
}
