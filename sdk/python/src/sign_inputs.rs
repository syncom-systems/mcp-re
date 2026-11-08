// SPDX-License-Identifier: Apache-2.0
//! The signing arguments as the Python API names them, grouped so one value carries a call
//! from the keyword list to `mcp-re-binding-core`: which message is signed, where it is
//! addressed, and the window it is valid for.

use mcp_re_binding_core::Call;
use mcp_re_binding_core::ContinuationArgs;
use mcp_re_binding_core::SignArgs;

/// The Unix-second window a signature is valid for.
pub(crate) struct Window {
    pub(crate) created: i64,
    pub(crate) expires: i64,
}

/// What a signing call names, apart from the custody (seed or device) and the call kind.
pub(crate) struct Signing<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) method: &'a str,
    pub(crate) params_json: &'a str,
    pub(crate) target_uri: &'a str,
    pub(crate) audience_id: &'a str,
    pub(crate) route: Option<String>,
    pub(crate) dpop_token: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) window: Window,
    pub(crate) bindings_json: Option<String>,
}

impl Signing<'_> {
    /// The binding core's signing arguments for `call`.
    pub(crate) fn args(self, call: Call) -> SignArgs {
        SignArgs {
            call,
            key_id: self.key_id.to_owned(),
            method: self.method.to_owned(),
            params_json: self.params_json.to_owned(),
            target_uri: self.target_uri.to_owned(),
            audience_id: self.audience_id.to_owned(),
            route: self.route,
            dpop_token: self.dpop_token.to_owned(),
            nonce: self.nonce.to_owned(),
            created: self.window.created,
            expires: self.window.expires,
            bindings_json: self.bindings_json,
        }
    }
}

/// A request call: its id, and the ADR-MCPS-047 answer-leg handles, all five or none.
pub(crate) fn request_call(id_json: &str, continuation: ContinuationArgs) -> Call {
    Call::Request {
        id_json: id_json.to_owned(),
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

    #[test]
    fn the_five_continuation_keywords_reach_their_own_handles() {
        let call = request_call(
            "7",
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
        let args = Signing {
            key_id: "k",
            method: "m",
            params_json: "p",
            target_uri: "t",
            audience_id: "a",
            route: Some("r".into()),
            dpop_token: "d",
            nonce: "n",
            window: Window {
                created: 1,
                expires: 2,
            },
            bindings_json: Some("b".into()),
        }
        .args(Call::Notification);
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
}
