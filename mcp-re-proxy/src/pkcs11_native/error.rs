//! The failure type of the PKCS#11 / FFI path, and the one place a raw `CK_RV` becomes a
//! decision.

use cryptoki_sys::CKR_OK;
use cryptoki_sys::CK_RV;

/// A failure on the PKCS#11 / FFI path. Carries human-readable context only —
/// never any secret material. The keysource maps these onto its own `KeyError`.
#[derive(Debug)]
pub enum Pkcs11Error {
    /// The module was refused by the executable-path floor or could not be loaded,
    /// or `C_GetFunctionList` was unavailable / returned null. (Bootstrap failures.)
    Load(String),
    /// A required function-list entry was a null pointer (the module does not
    /// implement that PKCS#11 function). Fail closed rather than call null.
    MissingFunction(String),
    /// A PKCS#11 call returned a non-`CKR_OK` status. Carries the operation and
    /// the raw `CK_RV` for diagnosis.
    Ck { op: String, rv: CK_RV },
    /// A returned value had an unexpected shape (e.g. a length that does not fit
    /// the two-call idiom). Fail closed.
    Protocol(String),
}

impl std::fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkcs11Error::Load(msg) => write!(f, "{msg}"),
            Pkcs11Error::MissingFunction(name) => {
                write!(
                    f,
                    "module does not export {name} (null function-list entry)"
                )
            }
            Pkcs11Error::Ck { op, rv } => write!(f, "{op}: CK_RV 0x{rv:08x}"),
            Pkcs11Error::Protocol(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Pkcs11Error {}

/// Map a raw `CK_RV` to `Ok(())` on `CKR_OK`, else a contextual [`Pkcs11Error`].
pub(super) fn check(rv: CK_RV, op: &str) -> Result<(), Pkcs11Error> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(Pkcs11Error::Ck {
            op: op.to_string(),
            rv,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `check` is the one place a `CK_RV` becomes a decision: only `CKR_OK` passes, and
    /// everything else carries the operation name and the raw status for diagnosis.
    #[test]
    fn only_ckr_ok_passes_the_status_check() {
        assert!(check(CKR_OK, "C_Sign").is_ok());
        match check(0x0000_0082, "C_Sign") {
            Err(Pkcs11Error::Ck { op, rv }) => {
                assert_eq!(op, "C_Sign");
                assert_eq!(rv, 0x0000_0082);
            }
            other => panic!("a non-CKR_OK status must fail closed, got {other:?}"),
        }
    }

    /// Every wrapper failure renders with its context and never with a bare code.
    #[test]
    fn every_wrapper_error_renders_its_context() {
        assert_eq!(format!("{}", Pkcs11Error::Load("boom".to_string())), "boom");
        assert_eq!(
            format!("{}", Pkcs11Error::MissingFunction("C_Sign".to_string())),
            "module does not export C_Sign (null function-list entry)"
        );
        assert_eq!(
            format!(
                "{}",
                Pkcs11Error::Ck {
                    op: "C_Login".to_string(),
                    rv: 0x0000_00a0
                }
            ),
            "C_Login: CK_RV 0x000000a0"
        );
        assert_eq!(
            format!("{}", Pkcs11Error::Protocol("shape".to_string())),
            "shape"
        );
    }
}
