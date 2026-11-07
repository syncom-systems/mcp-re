//! The owned object-lookup template handed to `C_FindObjectsInit`.

use std::ffi::c_void;

use cryptoki_sys::CKA_CLASS;
use cryptoki_sys::CKA_KEY_TYPE;
use cryptoki_sys::CKA_LABEL;
use cryptoki_sys::CKK_EC_EDWARDS;
use cryptoki_sys::CKO_PRIVATE_KEY;
use cryptoki_sys::CKO_PUBLIC_KEY;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_OBJECT_CLASS;
use cryptoki_sys::CK_ULONG;

/// Object class selector for [`AttributeTemplate`], mirroring the two PKCS#11
/// object classes this wrapper needs.
#[derive(Clone, Copy)]
pub enum ObjectClass {
    /// `CKO_PRIVATE_KEY`.
    Private,
    /// `CKO_PUBLIC_KEY`.
    Public,
}

impl ObjectClass {
    fn ck_value(self) -> CK_OBJECT_CLASS {
        match self {
            ObjectClass::Private => CKO_PRIVATE_KEY,
            ObjectClass::Public => CKO_PUBLIC_KEY,
        }
    }
}

/// An OWNED Ed25519 object-lookup template: `CKA_CLASS` + `CKA_KEY_TYPE`
/// (`CKK_EC_EDWARDS`) + `CKA_LABEL`. It owns the backing scalar/byte storage so
/// the `CK_ATTRIBUTE` array it lends out via [`as_ck_attributes`] points at
/// memory that lives at least as long as `self` — the borrow checker enforces the
/// `C_FindObjectsInit` call cannot outlive this template.
pub struct AttributeTemplate {
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    label: Vec<u8>,
}

impl AttributeTemplate {
    /// Build the Ed25519 lookup template for `class` objects labelled `label`.
    pub fn ed25519_labelled(class: ObjectClass, label: &str) -> Self {
        AttributeTemplate {
            class: class.ck_value(),
            key_type: CKK_EC_EDWARDS,
            label: label.as_bytes().to_vec(),
        }
    }

    /// Borrow the three attributes as a `CK_ATTRIBUTE` array. Each entry points
    /// into `self`'s owned fields, so the returned `Vec` must not outlive `self`
    /// (it borrows `&self`, so it cannot).
    pub(super) fn as_ck_attributes(&self) -> Vec<CK_ATTRIBUTE> {
        vec![
            ck_attr(CKA_CLASS, &self.class),
            ck_attr(CKA_KEY_TYPE, &self.key_type),
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: self.label.as_ptr() as *mut c_void,
                ulValueLen: self.label.len() as CK_ULONG,
            },
        ]
    }
}

/// Build a `CK_ATTRIBUTE` whose value is a single borrowed scalar (`CK_ULONG`-
/// width: object class or key type). The pointer borrows `value`, so the caller
/// must keep `value` alive for as long as the attribute is used.
fn ck_attr<T>(type_: CK_ATTRIBUTE_TYPE, value: &T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: value as *const T as *mut c_void,
        ulValueLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lookup template is the ONLY thing asked of the token when a key is found, so
    /// its three attributes are pinned here: the object class, `CKK_EC_EDWARDS`, and the
    /// label as exact bytes with no NUL terminator and no padding.
    #[test]
    fn the_lookup_template_constrains_class_key_type_and_label() {
        let template = AttributeTemplate::ed25519_labelled(ObjectClass::Private, "signing");
        assert_eq!(template.class, CKO_PRIVATE_KEY);
        assert_eq!(template.key_type, CKK_EC_EDWARDS);
        assert_eq!(template.label, &b"signing"[..]);

        let attrs = template.as_ck_attributes();
        let [class, key_type, label] = attrs.as_slice() else {
            panic!(
                "the Ed25519 lookup asks for exactly three attributes, got {}",
                attrs.len()
            );
        };
        assert_eq!(class.type_, CKA_CLASS);
        assert_eq!(key_type.type_, CKA_KEY_TYPE);
        assert_eq!(label.type_, CKA_LABEL);
        assert_eq!(label.ulValueLen as usize, "signing".len());
        assert_eq!(
            ObjectClass::Public.ck_value(),
            CKO_PUBLIC_KEY,
            "the public arm must not silently resolve to the private class"
        );
    }
}
