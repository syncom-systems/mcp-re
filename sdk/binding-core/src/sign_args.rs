// SPDX-License-Identifier: Apache-2.0
//! The arguments of one signing call, and how they are read into the core's signing inputs.
//!
//! The reading order is the refusal order both hosts have always had: the id, the params,
//! the provider bindings, then the DPoP credential and the continuation. The two refusals
//! of the last pair are `mcp-re-client-core`'s rather than this file's: an empty
//! `dpop_token` ([`DpopCredential`]) instead of a binding over zero bytes beside a signed
//! `Authorization: Bearer ` header carrying nothing, and a partially supplied continuation
//! ([`ContinuationHandles`]) instead of an answer leg silently sent as a new call.

use mcp_re_client_core::build_authorization;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::ContinuationHandles;
use mcp_re_client_core::DpopCredential;
use mcp_re_client_core::ProvidedAuthorization;
use mcp_re_client_core::RequestSigningInputs;
use serde_json::Map;
use serde_json::Value;

use crate::BindingError;

/// One message to sign: the audience it is for, its DPoP credential, its anti-replay nonce
/// and window, and the provider-supplied artifact bindings (ADR-MCPS-044
/// §Authorization-binding hook), as a JSON array of specs carrying the artifact material.
///
/// `created` and `expires` are Unix seconds; each host converts its own number type into
/// them before this value exists. An absent `bindings_json` means DPoP only.
#[derive(Debug, Clone)]
pub struct SignArgs {
    pub call: Call,
    pub key_id: String,
    pub method: String,
    pub params_json: String,
    pub target_uri: String,
    pub audience_id: String,
    pub route: Option<String>,
    pub dpop_token: String,
    pub nonce: String,
    pub created: i64,
    pub expires: i64,
    pub bindings_json: Option<String>,
}

/// Whether the message is a request, which receives a result, or a notification, which
/// does not and so carries no id and cannot be an ADR-MCPS-047 answer leg.
#[derive(Debug, Clone)]
pub enum Call {
    Request {
        id_json: String,
        continuation: ContinuationArgs,
    },
    Notification,
}

/// The ADR-MCPS-047 answer-leg handles as the caller supplied them: all five or none.
///
/// The previous-request evidence digest (this client's open-leg sign handle), the
/// input-required-response evidence digest (the open-leg verify handle), and the opaque
/// `requestState`.
#[derive(Debug, Clone, Default)]
pub struct ContinuationArgs {
    pub prev_alg: Option<String>,
    pub prev_value: Option<String>,
    pub irr_alg: Option<String>,
    pub irr_value: Option<String>,
    pub request_state: Option<String>,
}

/// A signing call read into the values the core's builders take. `id` is `None` for a
/// notification.
pub(crate) struct Message {
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    pub(crate) params: Map<String, Value>,
    pub(crate) target_uri: String,
    pub(crate) inputs: RequestSigningInputs,
}

impl SignArgs {
    pub(crate) fn read(self) -> Result<Message, BindingError> {
        let (id, continuation) = match self.call {
            Call::Request {
                id_json,
                continuation,
            } => (Some(parse_json(&id_json, "id")?), continuation),
            Call::Notification => (None, ContinuationArgs::default()),
        };
        let params = params_object(&self.params_json)?;
        let provided = provided_authorization(self.bindings_json.as_deref())?;
        let credential = DpopCredential::present(&self.dpop_token)
            .map_err(|e| BindingError::Local(e.to_string()))?;
        let handles = ContinuationHandles::from_optional(
            continuation.prev_alg,
            continuation.prev_value,
            continuation.irr_alg,
            continuation.irr_value,
            continuation.request_state,
        )
        .map_err(|e| BindingError::Local(e.to_string()))?;
        let audience = AudienceTuple {
            audience_id: self.audience_id,
            target_uri: self.target_uri.clone(),
            route: self.route,
        };
        // DPoP is the built-in, header-derived binding: its credential is the covered
        // `Authorization: Bearer` header, so it is never provider-supplied. Provider
        // bindings follow it.
        let mut bindings = vec![credential.binding()];
        bindings.extend(provided.bindings);
        let mut inputs = RequestSigningInputs::new(
            self.key_id,
            audience,
            bindings,
            self.nonce,
            self.created,
            self.expires,
        )
        .with_headers(vec![(
            "Authorization".to_owned(),
            credential.authorization_header_value(),
        )]);
        if let Some(handles) = handles {
            inputs = inputs.with_continuation(handles.continuation());
        }
        if let Some(jws) = provided.decision {
            // The document goes in; the `pdp-decision` binding over it is minted there,
            // from these exact bytes, so nothing here can make the two disagree.
            inputs = inputs.with_authorization_decision(jws);
        }
        Ok(Message {
            id,
            method: self.method,
            params,
            target_uri: self.target_uri,
            inputs,
        })
    }
}

/// A provider list as the bindings and decision it contributes; absent is none.
fn provided_authorization(
    bindings_json: Option<&str>,
) -> Result<ProvidedAuthorization, BindingError> {
    match bindings_json {
        Some(json) => Ok(build_authorization(json)?),
        None => Ok(ProvidedAuthorization::default()),
    }
}

fn parse_json(s: &str, what: &str) -> Result<Value, BindingError> {
    serde_json::from_str(s).map_err(|e| BindingError::Local(format!("invalid {what} json: {e}")))
}

fn params_object(params_json: &str) -> Result<Map<String, Value>, BindingError> {
    match parse_json(params_json, "params")? {
        Value::Object(m) => Ok(m),
        _ => Err(BindingError::Local("params must be a JSON object".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::Call;
    use super::ContinuationArgs;
    use super::SignArgs;
    use crate::BindingError;

    fn args(call: Call) -> SignArgs {
        SignArgs {
            call,
            key_id: "client-1".into(),
            method: "tools/call".into(),
            params_json: r#"{"name":"echo"}"#.into(),
            target_uri: "https://example.com/mcp".into(),
            audience_id: "aud".into(),
            route: None,
            dpop_token: "tok".into(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            created: 1_000,
            expires: 1_060,
            bindings_json: None,
        }
    }

    fn request(id_json: &str, continuation: ContinuationArgs) -> Call {
        Call::Request {
            id_json: id_json.into(),
            continuation,
        }
    }

    fn refusal(args: SignArgs) -> BindingError {
        match args.read() {
            Ok(_) => panic!("the arguments must be refused"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_request_reads_its_id_and_a_notification_has_none() {
        let read = args(request("7", ContinuationArgs::default()))
            .read()
            .expect("a request reads");
        assert_eq!(read.id, Some(serde_json::json!(7)));
        let note = args(Call::Notification)
            .read()
            .expect("a notification reads");
        assert_eq!(note.id, None);
    }

    #[test]
    fn the_arguments_are_refused_in_order_with_the_messages_the_hosts_raise() {
        let mut every_fault = args(request("{", ContinuationArgs::default()));
        every_fault.params_json = "[]".into();
        every_fault.bindings_json = Some("{".into());
        every_fault.dpop_token = String::new();
        let BindingError::Local(reason) = refusal(every_fault.clone()) else {
            panic!("a malformed id is refused first, as a local refusal");
        };
        assert!(reason.starts_with("invalid id json: "), "{reason}");
        every_fault.call = request("1", ContinuationArgs::default());
        assert_eq!(
            refusal(every_fault.clone()),
            BindingError::Local("params must be a JSON object".into())
        );
        every_fault.params_json = "{}".into();
        assert!(matches!(
            refusal(every_fault.clone()),
            BindingError::Wire(_)
        ));
        every_fault.bindings_json = None;
        assert!(matches!(refusal(every_fault), BindingError::Local(_)));
    }

    #[test]
    fn a_partial_continuation_is_refused_not_dropped() {
        let partial = ContinuationArgs {
            prev_alg: Some("sha-256".into()),
            ..ContinuationArgs::default()
        };
        assert!(matches!(
            refusal(args(request("1", partial))),
            BindingError::Local(_)
        ));
    }
}
