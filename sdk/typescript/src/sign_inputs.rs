// SPDX-License-Identifier: Apache-2.0
//! The signing arguments as the TypeScript API names them, grouped so one value carries a
//! call from the parameter list to `mcp-re-binding-core`: which message is signed, where it
//! is addressed, and the window it is valid for.

use mcp_re_binding_core::Call;
use mcp_re_binding_core::ContinuationArgs;
use mcp_re_binding_core::SignArgs;

use super::refusal::Refusal;
use super::whole_seconds;

/// The window a signature is valid for, as the JS numbers the caller passed.
pub(crate) struct Window {
    pub(crate) created: f64,
    pub(crate) expires: f64,
}

/// What a signing call names, apart from the custody (seed or device) and the call kind.
pub(crate) struct Signing {
    pub(crate) key_id: String,
    pub(crate) method: String,
    pub(crate) params_json: String,
    pub(crate) target_uri: String,
    pub(crate) audience_id: String,
    pub(crate) route: Option<String>,
    pub(crate) dpop_token: String,
    pub(crate) nonce: String,
    pub(crate) window: Window,
    pub(crate) bindings_json: Option<String>,
}

impl Signing {
    /// The binding core's signing arguments for `call`, refusing a window that is not whole
    /// in-range seconds.
    pub(crate) fn args(self, call: Call) -> Result<SignArgs, Refusal> {
        Ok(SignArgs {
            call,
            key_id: self.key_id,
            method: self.method,
            params_json: self.params_json,
            target_uri: self.target_uri,
            audience_id: self.audience_id,
            route: self.route,
            dpop_token: self.dpop_token,
            nonce: self.nonce,
            created: whole_seconds(self.window.created, "created")?,
            expires: whole_seconds(self.window.expires, "expires")?,
            bindings_json: self.bindings_json,
        })
    }
}

/// A request call: its id, and the ADR-MCPS-047 answer-leg handles, all five or none.
pub(crate) fn request_call(id_json: String, continuation: ContinuationArgs) -> Call {
    Call::Request {
        id_json,
        continuation,
    }
}

#[cfg(test)]
mod tests {
    use super::request_call;
    use super::Signing;
    use super::Window;
    use mcp_re_binding_core::Call;
    use mcp_re_binding_core::ContinuationArgs;

    fn signing(window: Window) -> Signing {
        Signing {
            key_id: "k".into(),
            method: "m".into(),
            params_json: "p".into(),
            target_uri: "t".into(),
            audience_id: "a".into(),
            route: Some("r".into()),
            dpop_token: "d".into(),
            nonce: "n".into(),
            window,
            bindings_json: Some("b".into()),
        }
    }

    #[test]
    fn the_five_continuation_keys_reach_their_own_handles() {
        let call = request_call(
            "7".into(),
            ContinuationArgs {
                prev_alg: Some("a".into()),
                prev_value: Some("b".into()),
                irr_alg: Some("c".into()),
                irr_value: Some("d".into()),
                request_state: Some("e".into()),
            },
        );
        let Call::Request {
            id_json,
            continuation,
        } = call
        else {
            panic!("a request call");
        };
        assert_eq!(id_json, "7");
        assert_eq!(continuation.prev_alg.as_deref(), Some("a"));
        assert_eq!(continuation.prev_value.as_deref(), Some("b"));
        assert_eq!(continuation.irr_alg.as_deref(), Some("c"));
        assert_eq!(continuation.irr_value.as_deref(), Some("d"));
        assert_eq!(continuation.request_state.as_deref(), Some("e"));
    }

    #[test]
    fn each_signing_value_reaches_its_own_argument() {
        let args = signing(Window {
            created: 1.0,
            expires: 2.0,
        })
        .args(Call::Notification);
        let Ok(args) = args else {
            panic!("a whole window is not refused");
        };
        assert_eq!(
            [
                args.key_id.as_str(),
                &args.method,
                &args.params_json,
                &args.target_uri,
                &args.audience_id,
                &args.dpop_token,
                &args.nonce,
            ],
            ["k", "m", "p", "t", "a", "d", "n"]
        );
        assert_eq!(args.route.as_deref(), Some("r"));
        assert_eq!(args.bindings_json.as_deref(), Some("b"));
        assert_eq!((args.created, args.expires), (1, 2));
    }

    #[test]
    fn a_window_that_is_not_whole_seconds_is_refused_by_name() {
        for (created, expires, named) in [(0.5, 2.0, "created"), (1.0, f64::NAN, "expires")] {
            let Err(refused) = signing(Window { created, expires }).args(Call::Notification) else {
                panic!("{created}/{expires} must be refused");
            };
            assert!(refused.reason.starts_with(named), "{}", refused.reason);
        }
    }
}
