//! The mock token's state: key objects, sessions and login.

use std::collections::HashMap;
use std::sync::Mutex;

use cryptoki_sys::CKR_GENERAL_ERROR;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_OBJECT_CLASS;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use ed25519_dalek::SigningKey;

/// A key object resident on the mock token.
pub(crate) struct KeyObject {
    pub(crate) handle: CK_OBJECT_HANDLE,
    pub(crate) class: CK_OBJECT_CLASS,
    pub(crate) key_type: CK_KEY_TYPE,
    pub(crate) label: Vec<u8>,
    /// Present only for signable (`CKK_EC_EDWARDS`) objects.
    pub(crate) signing: Option<SigningKey>,
    /// The `CKA_EC_POINT` value returned for this object: a DER `OCTET STRING`
    /// wrapping the 32-byte Edwards point (`0x04 0x20 || point`), matching what a
    /// real token returns and what the client's `raw_ed25519_point` accepts.
    pub(crate) ec_point: Vec<u8>,
    /// Whether the token may let this key leave it: the reverse of a provisioned
    /// non-exportable key. Reported only for private objects.
    pub(crate) exportable: bool,
}

/// In-progress `C_FindObjects` iteration state for a session.
pub(crate) struct FindState {
    pub(crate) matches: Vec<CK_OBJECT_HANDLE>,
    pub(crate) pos: usize,
}

/// An open session.
pub(crate) struct Session {
    pub(crate) find: Option<FindState>,
    pub(crate) sign_key: Option<CK_OBJECT_HANDLE>,
}

/// The whole mock token state, rebuilt from the environment on each `C_Initialize`.
pub(crate) struct State {
    pub(crate) token_label: String,
    pub(crate) objects: Vec<KeyObject>,
    pub(crate) sessions: HashMap<CK_SESSION_HANDLE, Session>,
    pub(crate) next_session: CK_SESSION_HANDLE,
    /// Login state is per application per token, not per session: set by the first
    /// `C_Login`, cleared when the last session closes.
    pub(crate) logged_in: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

impl State {
    pub(crate) fn object(&self, handle: CK_OBJECT_HANDLE) -> Option<&KeyObject> {
        self.objects.iter().find(|o| o.handle == handle)
    }
}

/// Run `f` against the initialized token; before `C_Initialize` (or after `C_Finalize`)
/// the call fails with `CKR_GENERAL_ERROR`.
pub(crate) fn with_state(f: impl FnOnce(&mut State) -> CK_RV) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    match guard.as_mut() {
        Some(state) => f(state),
        None => CKR_GENERAL_ERROR,
    }
}

/// Replace the token with a freshly built one (`C_Initialize`), or drop it (`C_Finalize`).
pub(crate) fn replace_state(next: Option<State>) {
    *STATE.lock().expect("mock state lock") = next;
}
