//! `C_FindObjects*`: selecting key objects by class, key type and label.

use std::os::raw::c_ulong;

use cryptoki_sys::CKA_CLASS;
use cryptoki_sys::CKA_KEY_TYPE;
use cryptoki_sys::CKA_LABEL;
use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_GENERAL_ERROR;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_OBJECT_CLASS;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;

use super::state::with_state;
use super::state::FindState;
use super::state::KeyObject;

/// The `(class, key_type, label)` selector a find template carries; an absent field
/// matches everything.
#[derive(Default)]
struct Selector {
    class: Option<CK_OBJECT_CLASS>,
    key_type: Option<CK_KEY_TYPE>,
    label: Option<Vec<u8>>,
}

impl Selector {
    /// Read the selector out of a Cryptoki attribute template.
    ///
    /// # Safety
    /// `templ` must be null or point at `count` readable attributes, each of whose
    /// non-null `pValue` points at `ulValueLen` readable bytes.
    unsafe fn from_template(templ: *mut CK_ATTRIBUTE, count: c_ulong) -> Selector {
        let attrs: &[CK_ATTRIBUTE] = if templ.is_null() || count == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(templ, count as usize)
        };
        let mut selector = Selector::default();
        for attr in attrs.iter().filter(|a| !a.pValue.is_null()) {
            selector.read(attr);
        }
        selector
    }

    unsafe fn read(&mut self, attr: &CK_ATTRIBUTE) {
        let kind = attr.type_ as CK_ATTRIBUTE_TYPE;
        if kind == CKA_CLASS {
            self.class = Some(*(attr.pValue as *const CK_OBJECT_CLASS));
        } else if kind == CKA_KEY_TYPE {
            self.key_type = Some(*(attr.pValue as *const CK_KEY_TYPE));
        } else if kind == CKA_LABEL {
            let bytes =
                std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
            self.label = Some(bytes.to_vec());
        }
    }

    fn matches(&self, o: &KeyObject) -> bool {
        self.class.is_none_or(|c| c == o.class)
            && self.key_type.is_none_or(|k| k == o.key_type)
            && self
                .label
                .as_ref()
                .is_none_or(|l| l.as_slice() == o.label.as_slice())
    }
}

pub(crate) unsafe extern "C" fn c_find_objects_init(
    session: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    count: c_ulong,
) -> CK_RV {
    with_state(|state| {
        let selector = Selector::from_template(templ, count);
        let matches: Vec<CK_OBJECT_HANDLE> = state
            .objects
            .iter()
            .filter(|o| selector.matches(o))
            .map(|o| o.handle)
            .collect();
        let Some(sess) = state.sessions.get_mut(&session) else {
            return CKR_GENERAL_ERROR;
        };
        sess.find = Some(FindState { matches, pos: 0 });
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn c_find_objects(
    session: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: c_ulong,
    object_count: *mut c_ulong,
) -> CK_RV {
    if object.is_null() || object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(find) = state
            .sessions
            .get_mut(&session)
            .and_then(|sess| sess.find.as_mut())
        else {
            return CKR_GENERAL_ERROR;
        };
        let remaining = &find.matches[find.pos..];
        let n = remaining.len().min(max_object_count as usize);
        for (i, h) in remaining[..n].iter().enumerate() {
            *object.add(i) = *h;
        }
        find.pos += n;
        *object_count = n as c_ulong;
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn c_find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if let Some(sess) = state.sessions.get_mut(&session) {
            sess.find = None;
        }
        CKR_OK
    })
}
