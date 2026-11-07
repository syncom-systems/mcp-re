//! A hermetic MOCK PKCS#11 (Cryptoki) provider for the `mcp-re-proxy` PKCS#11
//! response-signing / delegated-TLS e2e test.
//!
//! This `cdylib` exports `C_GetFunctionList` and implements EXACTLY the Cryptoki
//! surface that `mcp-re-proxy`'s PKCS#11 client (`pkcs11_native.rs`) calls — nothing
//! more:
//!   `C_Initialize` / `C_Finalize`, `C_GetSlotList` / `C_GetTokenInfo`,
//!   `C_OpenSession` / `C_CloseSession`, `C_Login`,
//!   `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`,
//!   `C_SignInit` / `C_Sign` (`CKM_EDDSA`), `C_GetAttributeValue` (`CKA_EC_POINT`, and
//!   `CKA_SENSITIVE` / `CKA_EXTRACTABLE` on a private key).
//! Every other function-list slot is left NULL, so if the client ever reached for
//! one the client's own `func!` guard would surface a `MissingFunction` error.
//!
//! It is a TEST DOUBLE, not a key store: keys live only in this process's memory
//! for the duration of the test, seeded DETERMINISTICALLY from `SHA-256(label ||
//! id)` so a public point read off a mock object always matches the signature the
//! mock produces for it — across `C_Finalize` → `C_Initialize` cycles. The object
//! set and token label are supplied by the test via two environment variables read
//! at `C_Initialize`:
//!   * `MOCK_PKCS11_TOKEN_LABEL` — the label reported by `C_GetTokenInfo`.
//!   * `MOCK_PKCS11_OBJECTS`     — `;`-separated `label,keytype,id` entries, where
//!     `keytype` is `ed25519` (a signable `CKK_EC_EDWARDS` key pair),
//!     `ed25519-misbound` (the same, but the private object signs with a key other than
//!     the advertised one), `ed25519-extractable` (the same as `ed25519`, but the private
//!     object reports `CKA_SENSITIVE = false` and `CKA_EXTRACTABLE = true`) or `ec` (a
//!     `CKK_EC` object used only to prove a non-Ed25519 TLS key is rejected).
//!
//! Each entry materialises BOTH a `CKO_PRIVATE_KEY` and a `CKO_PUBLIC_KEY` object
//! sharing that label/id, mirroring how a real token stores a generated key pair.

mod attributes;
mod find;
mod function_list;
mod session;
mod sign;
mod state;
mod token;

use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CK_FUNCTION_LIST;
use cryptoki_sys::CK_RV;

/// The one symbol a PKCS#11 module MUST export. `#[no_mangle] extern "C"`.
///
/// # Safety
/// `pp_list` must be a valid, writable `*mut *mut CK_FUNCTION_LIST` (the loader's
/// out-parameter), per the Cryptoki ABI.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if pp_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_list = function_list::function_list_ptr();
    CKR_OK
}
