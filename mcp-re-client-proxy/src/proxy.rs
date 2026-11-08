// SPDX-License-Identifier: Apache-2.0
//! The local client-side MCP-RE proxy pipeline (MCPS-49, #196), on the RFC 9421
//! carrier (ADR-MCPRE-050).
//!
//! The local client speaks PLAIN MCP to this proxy; the proxy signs the outbound
//! request as RFC 9421 + RFC 9530 via `mcp-re-client-core`, forwards it to the
//! remote MCP-RE endpoint, verifies the signed response bound to that request, and
//! returns PLAIN MCP. The local client never emits, parses, or negotiates any
//! MCP-RE field; the signature rides in the RFC 9421 HTTP headers, not a JSON-RPC
//! `_meta` block.
//!
//! ## PURGE 2026-07-11 — lean RFC 9421 pipeline
//! The object-era enforcement-mode engine, in-flight correlation store, MRT
//! continuation retention, and authorization-binding providers are **deferred**
//! (rebuilt on RFC 9421 later); this is the signing/verification adapter core.

use mcp_re_client_core::build_signed_message;
use mcp_re_client_core::response::verify_delegated_accepted_202_pinned;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ExecutionContract;
use mcp_re_client_core::McpMessage;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_core::SigningKey;
use serde_json::Map;
use serde_json::Value;

mod arrival;
mod plain_reply;

use arrival::request_id;
use arrival::Arrival;
pub(crate) use plain_reply::plain_error_from_rejection;
pub(crate) use plain_reply::plain_response_from_verified;

use crate::verified_outcome::read_notification_rejection;
use crate::verified_outcome::read_outcome;

use crate::route::RouteRegistry;
use crate::transport::ProxyError;
use crate::transport::RemoteTransport;

/// Per-call parameters the mode-specific layer supplies (RFC 9421 freshness + the
/// verification clock). The binary fills these from its nonce source and clock.
#[derive(Clone)]
pub struct CallParams<'a> {
    /// A fresh anti-replay nonce (RFC 9421 `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Clock (Unix seconds) for response verification, read once by `handle` after the
    /// transport returns so the reply is judged at the instant it arrived.
    pub verification_clock: &'a dyn Fn() -> i64,
}

impl std::fmt::Debug for CallParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallParams")
            .field("nonce", &self.nonce)
            .field("created", &self.created)
            .field("expires", &self.expires)
            .field("verification_clock", &"<clock>")
            .finish()
    }
}

/// The proxy's response to the local client: plain MCP, plus the verified kind so
/// the embedding layer can distinguish a genuine success from a provably-denied
/// request (a verified rejection receipt) without re-parsing.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The plain MCP JSON-RPC response to return to the local client — a `result`
    /// on success, or a JSON-RPC `error` when the server provably rejected.
    pub plain_response: Value,
    /// Whether the verified response was a success or a delegated rejection receipt.
    pub kind: ResponseKind,
}

/// The verified outcome the proxy hands its embedding layer. A verified REJECTION is
/// NOT a proxy failure — the server provably denied the request; the proxy converts
/// the signed receipt to a plain JSON-RPC error and reports the classification. An
/// UNVERIFIABLE response (unsigned / direct-root in delegated mode / bad signature)
/// is a `ProxyError` instead — the channel is compromised or misconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    /// A verified TERMINAL success response — the call completed.
    Success,
    /// A verified NON-TERMINAL `InputRequiredResult`: the server is awaiting a signed
    /// answer leg, carrying `request_state` to present on it.
    ///
    /// Distinct from [`Success`](ResponseKind::Success) because the two are different
    /// events and the difference is not recoverable from the plain body once it has
    /// been handed over. Reporting this as a success is how an elicitation — a
    /// human-approval round trip — gets delivered to an application as a finished
    /// tool result: the application then acts on an approval nobody gave, and no
    /// answer leg is ever signed.
    InputRequired {
        /// The opaque MRTR state the answer leg must re-present.
        request_state: String,
    },
    /// A verified signed bodyless 202 for a one-way NOTIFICATION: the enforcement
    /// boundary authenticated and accepted the message. It does NOT say any action
    /// completed.
    AcceptedNotification,
    /// A verified TERMINAL reply carrying a JSON-RPC `error` member: the exchange
    /// completed and the call did not succeed.
    ///
    /// Distinct from [`Success`](ResponseKind::Success) because `classify_result`
    /// reads the `result` member, and an error reply has none — so an absent `result`
    /// classifies as terminal and the failure would be announced to the local client
    /// as a completed call. The signature is equally valid either way; what differs is
    /// what the server said, and that difference is not recoverable once the header
    /// has been written.
    ///
    /// Distinct from [`VerifiedRejection`](ResponseKind::VerifiedRejection), which is
    /// the enforcement boundary refusing the request. This is the *inner tool* failing
    /// a request that was admitted.
    CallFailed {
        /// The JSON-RPC error code the server reported, when it is an integer.
        code: Option<i64>,
    },
    /// A verified delegated rejection receipt, converted to plain JSON-RPC error.
    /// `wire_code` is the server's frozen `mcp-re.*` reason; `bound` distinguishes a
    /// request-bound receipt from a preflight-unbound one.
    ///
    /// `execution` is the ADR-MCPRE-058 §10 contract the receipt carried. It is a
    /// field of this variant rather than something the embedder re-derives from the
    /// status, because the difference it names — a refusal that ran nothing versus one
    /// whose side effect a retry would perform a second time — is not recoverable from
    /// a status code, and 503 is the status clients retry.
    VerifiedRejection {
        wire_code: Option<String>,
        bound: bool,
        execution: ExecutionContract,
    },
    /// A verified rejection receipt for a one-way notification: no call to answer, so
    /// no id.
    RejectedNotification {
        wire_code: Option<String>,
        bound: bool,
        execution: ExecutionContract,
    },
}

/// The local client-side MCP-RE proxy. Holds the static route registry, the client
/// signing key + keyid, and the remote transport.
pub struct ClientProxy {
    registry: RouteRegistry,
    signing_key: SigningKey,
    key_id: String,
    transport: Box<dyn RemoteTransport>,
}

impl ClientProxy {
    /// Construct a proxy from its wired pieces.
    pub fn new(
        registry: RouteRegistry,
        signing_key: SigningKey,
        key_id: impl Into<String>,
        transport: Box<dyn RemoteTransport>,
    ) -> Self {
        ClientProxy {
            registry,
            signing_key,
            key_id: key_id.into(),
            transport,
        }
    }

    /// Handle one plain-MCP request on `route_id`: sign (RFC 9421) → forward →
    /// verify the bound signed response → return plain MCP. Fails closed on any
    /// verification failure.
    pub fn handle(
        &self,
        route_id: &str,
        plain_request: &Value,
        params: &CallParams<'_>,
    ) -> Result<ProxyResponse, ProxyError> {
        let route = self
            .registry
            .get(route_id)
            .ok_or_else(|| ProxyError::UnknownRoute(route_id.to_string()))?;

        // ABSENT `id` is what makes a JSON-RPC message a NOTIFICATION (§4.1), and both the
        // signer and the serving path classify on exactly that key's absence. `null` is not
        // the same thing: it is a PRESENT id, so defaulting to it turned every one-way
        // notification into a request the server dispatched to the backend and answered with
        // a bodied reply nothing was awaiting.
        let id = request_id(plain_request).cloned();
        let signed = self.sign_request(route, plain_request, params)?;

        // Forward to the remote MCP-RE endpoint.
        let response = self
            .transport
            .round_trip(signed.request())
            .map_err(ProxyError::Transport)?;
        let now_unix = (params.verification_clock)();

        // A NOTIFICATION is answered with a signed bodyless 202, not a bodied reply, so it
        // takes its own verification path. Nothing below applies: there is no result to
        // classify and no body to rebuild. It carries no `ResponseExpectation` either —
        // a bodyless 202 has no response block to bind one to — so the route's pin is
        // passed to it directly.
        let arrival = Arrival {
            response: &response,
            now_unix,
        };
        if id.is_none() {
            return self.verify_notification_ack(route, &signed, arrival);
        }
        let verified = self.verify_reply(route, &signed, arrival)?;

        // The request id the PROXY signed, not the one the server echoed. The plain
        // reply is addressed to the local client's outstanding call, and taking the id
        // from the response body would let the server redirect the answer.
        let request_id = id.unwrap_or(Value::Null);
        read_outcome(verified, &response, request_id)
    }

    /// Build the RFC 9421 signed request (or notification) this route sends.
    ///
    /// The shape follows the ID: a message with none is a NOTIFICATION and is signed as one,
    /// because both the signer and the serving path classify on exactly that key's absence.
    fn sign_request(
        &self,
        route: &crate::route::Route,
        plain_request: &Value,
        params: &CallParams<'_>,
    ) -> Result<mcp_re_client_core::SignedRequest, ProxyError> {
        let method = plain_request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProxyError::MalformedRequest)?
            .to_string();
        let req_params: Map<String, Value> = match plain_request.get("params") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(params)) => params.clone(),
            Some(_) => return Err(ProxyError::MalformedRequest),
        };

        // Sign the RFC 9421 request through the client-core seam.
        let inputs = RequestSigningInputs::new(
            self.key_id.clone(),
            route.audience.clone(),
            route.artifact_bindings.clone(),
            &params.nonce,
            params.created,
            params.expires,
        )
        .with_headers(route.extra_headers.clone());
        Ok(build_signed_message(
            McpMessage::new(request_id(plain_request), &method, req_params),
            &route.target_uri,
            &inputs,
            &self.signing_key,
        )?)
    }

    /// Verify the bound signed response under the route's REQUIRED profile.
    ///
    /// Configured profile = required profile: there is no cross-profile fallback, and both
    /// arms fail closed. ADR-MCPRE-052 delegated-signing is the only mode, so a
    /// delegated-signed success OR rejection receipt carrying the inline credential is what
    /// verifies; no direct-root, unsigned or object downgrade is accepted.
    ///
    /// The two variants differ ONLY in where the trust anchors come from, and the outcome
    /// handling is shared, so neither can drift into a laxer mapping.
    fn verify_reply(
        &self,
        route: &crate::route::Route,
        signed: &mcp_re_client_core::SignedRequest,
        arrival: Arrival<'_>,
    ) -> Result<mcp_re_client_core::VerifiedDelegatedResponse, ProxyError> {
        let Arrival { response, now_unix } = arrival;
        // Verify the signed response bound to THIS request under the route's required
        // profile (configured profile = required profile). Fail closed on any failure;
        // no cross-profile fallback.
        //
        // ADR-MCPRE-052 delegated-signing (the only mode): a delegated-signed success OR
        // rejection receipt carrying the inline credential. No direct-root / unsigned /
        // object downgrade is accepted (both verify functions fail closed). The two
        // variants differ ONLY in where the trust anchors come from; the outcome
        // handling below is shared, so neither can drift into a laxer mapping.
        let mut expectation = ResponseExpectation::for_signed(signed);
        // The route's PINNED credential ISSUER, if it configured one: without it any
        // server whose delegated credential chains to a trusted root and is scoped to
        // this audience may answer for this route. The pin is the ISSUER and not the
        // response-signing kid, which rotates every TTL; `route.expected_server_keyid`
        // keeps its published name.
        if let Some(keyid) = &route.expected_server_keyid {
            expectation = expectation.with_expected_issuer_kid(keyid.clone());
        }
        let verified = route.verification.with_trust(|trust, policy| {
            verify_delegated_response(response, trust, &expectation, policy, now_unix)
        })?;
        Ok(verified)
    }

    /// Verify the signed bodyless 202 that acknowledges a one-way NOTIFICATION.
    ///
    /// The 202 states that the enforcement boundary authenticated and ACCEPTED the
    /// message — not that any action completed. A notification is not delivered until
    /// this verifies, so an unverifiable ack is a `ProxyError`, never a silent success.
    ///
    /// The route's PINNED root issuer is enforced here on the same coordinate the
    /// bodied path pins. A pin that governs replies and not one-way notifications is a
    /// control an operator configured and the proxy did not run: on a route in an
    /// org-wide anchor set, any sibling holding a non-revoked delegated key under any
    /// listed root could otherwise acknowledge this route's `notifications/cancelled`.
    fn verify_notification_ack(
        &self,
        route: &crate::route::Route,
        signed: &mcp_re_client_core::SignedRequest,
        arrival: Arrival<'_>,
    ) -> Result<ProxyResponse, ProxyError> {
        let Arrival { response, now_unix } = arrival;
        // A non-2xx answer is a signed refusal verified exactly as a reply is.
        if !(200..300).contains(&response.status) {
            return read_notification_rejection(self.verify_reply(route, signed, arrival)?);
        }
        let pin = route.expected_server_keyid.as_deref();
        route.verification.with_trust(|trust, policy| {
            verify_delegated_accepted_202_pinned(
                response,
                signed.request(),
                trust,
                policy,
                pin,
                now_unix,
            )
        })?;
        Ok(ProxyResponse {
            // A notification has no reply. The plain JSON-RPC surface is empty rather
            // than a synthesized result the local client never asked for.
            plain_response: Value::Null,
            kind: ResponseKind::AcceptedNotification,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_client_core::HttpProfileError;
    use serde_json::json;

    use crate::route::ClientVerification;
    use mcp_re_client_core::HttpResponse;

    // ---------------------------------------------------------------------------------
    // Composition through `ClientProxy::handle`: a real delegated signing round trip over
    // the exact request `handle` signs (every signing input is fixed, and Ed25519 is
    // deterministic), so the route's configured controls are measured where they run.
    // ---------------------------------------------------------------------------------

    use mcp_re_client_core::ArtifactBinding;
    use mcp_re_client_core::ArtifactType;
    use mcp_re_client_core::AudienceTuple;
    use mcp_re_client_core::DelegationPolicy;
    use mcp_re_client_core::HttpRequest;
    use mcp_re_client_core::ResolvedActor;
    use mcp_re_client_core::ResolverOutcome;
    use mcp_re_client_core::SignedRequest;
    use mcp_re_client_core::SignerSlot;
    use mcp_re_client_core::StaticRevocationList;
    use mcp_re_client_core::TrustedIssuerSet;
    use mcp_re_http_profile::custody::DelegatedKeyWindow;
    use mcp_re_http_profile::custody::SigningWindow;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;
    use mcp_re_http_profile::DelegationClaims;
    use mcp_re_http_profile::DelegationHeader;
    use mcp_re_http_profile::PROFILE_TAG;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use crate::route::AnchorSnapshot;
    use crate::route::Route;
    use crate::transport::TransportError;

    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const CLIENT_KEY_ID: &str = "client-key-1";
    const ROOT_KID: &str = "root-kid";
    const AUD: &str = "verifier-1";
    const AUD_SCOPE: &str = "aud-scope-1";
    const EPOCH: &str = "epoch-1";
    const TARGET: &str = "https://mcp.example.com/mcp?route=a";
    /// One nonce per test process: `call_params` and `signed_for` must name the same nonce
    /// for the rebuilt request to be the one `handle` signed; its value is never asserted.
    fn nonce() -> &'static str {
        static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        NONCE.get_or_init(mcp_re_test_paths::unique_test_nonce)
    }
    const NOW: i64 = 1_700_000_100;
    const CREATED: i64 = 1_700_000_000;
    const EXPIRES: i64 = 1_700_000_300;
    const ROUTE_ID: &str = "r1";

    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&ROOT_SEED)
    }

    fn root_actor() -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: ROOT_KID.into(),
            },
            verification_key: root_key().public_key(),
            slot: SignerSlot::Response,
        }
    }

    fn policy() -> DelegationPolicy {
        DelegationPolicy::new(
            vec![AUD.to_string()],
            AUD_SCOPE,
            vec![EPOCH.to_string()],
            mcp_re_core::MaxClockSkew::new(60).expect("inside the bound"),
        )
    }

    fn custody() -> DelegatedSigningCustody<
        impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
        impl FnMut() -> SigningKey,
    > {
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(mcp_re_http_profile::issue_delegation_credential(
                &root, h, c,
            ))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        DelegatedSigningCustody::new(
            CustodyConfig {
                issuer_kid: ROOT_KID.into(),
                iss: "did:example:server".into(),
                profile: PROFILE_TAG.into(),
                aud: AUD.into(),
                audience_hash: AUD_SCOPE.into(),
                trust_epoch: EPOCH.parse().expect("epoch base"),
                server_role: "server".into(),
                server_trust_domain: "example.com".into(),
                server_subject: "did:example:server".into(),
                window: DelegatedKeyWindow::of(300, 60).expect("0 < overlap < ttl"),
            },
            root_key().public_key(),
            issue,
            factory,
        )
    }

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }

    fn bindings() -> Vec<ArtifactBinding> {
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"access-token-under-test",
        )]
    }

    fn call_params(verification_clock: &dyn Fn() -> i64) -> CallParams<'_> {
        CallParams {
            nonce: nonce().into(),
            created: CREATED,
            expires: EXPIRES,
            verification_clock,
        }
    }

    /// The request `handle` signs for `plain`, rebuilt from the same fixed inputs.
    fn signed_for(plain: &Value) -> SignedRequest {
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            nonce(),
            CREATED,
            EXPIRES,
        )
        .with_headers(Vec::new());
        let method = plain["method"].as_str().expect("a method");
        let params = plain["params"].as_object().cloned().unwrap_or_default();
        let key = SigningKey::from_seed_bytes(&CLIENT_SEED);
        build_signed_message(
            McpMessage::new(plain.get("id"), method, params),
            TARGET,
            &inputs,
            &key,
        )
        .expect("client signs")
    }

    /// A transport that answers every round trip with one precomputed response (or a
    /// transport failure when it holds none), counting the calls it receives.
    struct CannedTransport {
        response: Option<HttpResponse>,
        calls: Arc<AtomicUsize>,
    }

    impl RemoteTransport for CannedTransport {
        fn round_trip(
            &self,
            _request: &HttpRequest,
        ) -> Result<HttpResponse, crate::transport::TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.response
                .clone()
                .ok_or_else(|| TransportError::new("no canned response"))
        }
    }

    fn proxy_over(
        verification: ClientVerification,
        pin: Option<&str>,
        response: Option<HttpResponse>,
    ) -> (ClientProxy, Arc<AtomicUsize>) {
        let route = Route {
            route_id: ROUTE_ID.into(),
            target_uri: TARGET.into(),
            audience: audience(),
            artifact_bindings: bindings(),
            extra_headers: Vec::new(),
            expected_server_keyid: pin.map(str::to_owned),
            verification,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let proxy = ClientProxy::new(
            RouteRegistry::new().register(route),
            SigningKey::from_seed_bytes(&CLIENT_SEED),
            CLIENT_KEY_ID,
            Box::new(CannedTransport {
                response,
                calls: Arc::clone(&calls),
            }),
        );
        (proxy, calls)
    }

    fn required_verification() -> ClientVerification {
        ClientVerification::DelegatedRequired(
            policy(),
            Box::new(|kid: &str, slot: SignerSlot, _now: i64| match (kid, slot) {
                (ROOT_KID, SignerSlot::Response) => Some(root_actor()).into(),
                _ => None::<ResolvedActor>.into(),
            }),
            Box::new(StaticRevocationList::new()),
        )
    }

    fn anchored_verification() -> ClientVerification {
        ClientVerification::DelegatedAnchored(
            policy(),
            Arc::new(AnchorSnapshot::new(
                TrustedIssuerSet::new().with_current(root_actor()),
            )),
        )
    }

    fn reply_request() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read"}})
    }

    fn notification() -> Value {
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}})
    }

    fn delegated_reply(plain: &Value) -> HttpResponse {
        let signed = signed_for(plain);
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
        };
        custody()
            .sign_response(NOW, &mut response, signed.request())
            .expect("server delegated-signs the reply");
        response
    }

    fn delegated_202(plain: &Value) -> HttpResponse {
        let signed = signed_for(plain);
        let mut custody = custody();
        custody.ensure_active(NOW).expect("a credential is issued");
        let key = custody.active_snapshot().expect("a key is active");
        let window = SigningWindow::over(Arc::new(key), NOW, 300).expect("a live window");
        mcp_re_http_profile::sign_delegated_accepted_202(signed.request(), &window)
            .expect("the boundary signs the 202")
    }

    fn variants() -> [fn() -> ClientVerification; 2] {
        [required_verification, anchored_verification]
    }

    /// A signed refusal of a notification is a verdict, not a channel failure.
    #[test]
    fn a_verified_rejection_of_a_notification_is_a_rejection_not_a_gateway_failure() {
        let plain = notification();
        let signed = signed_for(&plain);
        let mut custody = custody();
        custody.ensure_active(NOW).expect("a credential is issued");
        let key = custody.active_snapshot().expect("a key is active");
        let window = SigningWindow::over(Arc::new(key), NOW, 300).expect("a live window");
        let response = mcp_re_http_profile::build_delegated_rejection(
            signed.request(),
            &mcp_re_http_profile::RejectionReason::new("mcp-re.replay_detected", "replayed"),
            409,
            &window,
        )
        .expect("the boundary builds a bound delegated rejection");
        for verification in variants() {
            let (proxy, _) = proxy_over(verification(), Some(ROOT_KID), Some(response.clone()));
            let out = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect("a verified refusal is an answer");
            assert_eq!(
                out.kind,
                ResponseKind::RejectedNotification {
                    wire_code: Some("mcp-re.replay_detected".into()),
                    bound: true,
                    execution: ExecutionContract::default(),
                }
            );
            assert!(out.plain_response.get("id").is_none());
            assert_eq!(
                out.plain_response["error"]["data"]["mcp_re_error"]["wire_code"],
                "mcp-re.replay_detected"
            );
        }
    }

    /// The route's issuer pin reaches verification of a bodied reply on both variants.
    #[test]
    fn a_pinned_route_refuses_a_reply_from_another_root_through_handle() {
        let plain = reply_request();
        let response = delegated_reply(&plain);
        for verification in variants() {
            let (proxy, _) = proxy_over(verification(), Some(ROOT_KID), Some(response.clone()));
            let out = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect("the pinned root's reply verifies");
            assert_eq!(out.kind, ResponseKind::Success);

            let (proxy, _) = proxy_over(
                verification(),
                Some("some-other-root-kid"),
                Some(response.clone()),
            );
            let err = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect_err("a reply from another root must be refused");
            assert_eq!(
                err,
                ProxyError::FailedClosed(HttpProfileError::ResponseBindingMismatch)
            );
        }
    }

    /// The same pin reaches verification of the bodyless 202 that acknowledges a
    /// notification, on both variants.
    #[test]
    fn a_pinned_route_refuses_a_202_from_another_root_through_handle() {
        let plain = notification();
        let response = delegated_202(&plain);
        for verification in variants() {
            let (proxy, _) = proxy_over(verification(), Some(ROOT_KID), Some(response.clone()));
            let out = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect("the pinned root's 202 verifies");
            assert_eq!(out.kind, ResponseKind::AcceptedNotification);

            let (proxy, _) = proxy_over(
                verification(),
                Some("some-other-root-kid"),
                Some(response.clone()),
            );
            let err = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect_err("a 202 from another root must be refused");
            assert_eq!(
                err,
                ProxyError::FailedClosed(HttpProfileError::ResponseBindingMismatch)
            );
        }
    }

    /// A `DelegatedRequired` resolver is consulted at the request's own `now`, so it can
    /// express a time-bounded trust decision.
    #[test]
    fn a_delegated_required_resolver_decides_at_the_request_now() {
        let plain = reply_request();
        let response = delegated_reply(&plain);
        let verification = || {
            ClientVerification::DelegatedRequired(
                policy(),
                Box::new(|kid: &str, slot: SignerSlot, now: i64| -> ResolverOutcome {
                    match (kid, slot) {
                        (ROOT_KID, SignerSlot::Response) if now < NOW + 10 => {
                            Some(root_actor()).into()
                        }
                        _ => None::<ResolvedActor>.into(),
                    }
                }),
                Box::new(StaticRevocationList::new()),
            )
        };
        let (proxy, _) = proxy_over(verification(), None, Some(response.clone()));
        proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
            .expect("trusted before the deadline");
        let (proxy, _) = proxy_over(verification(), None, Some(response));
        let err = proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW + 20))
            .expect_err("untrusted after the deadline");
        assert_eq!(
            err,
            ProxyError::FailedClosed(HttpProfileError::DelegationIssuerUntrusted)
        );
    }

    /// A transport whose round trip advances the shared clock, as a slow network would.
    struct SlowTransport {
        response: HttpResponse,
        clock: Arc<AtomicI64>,
    }

    impl RemoteTransport for SlowTransport {
        fn round_trip(&self, _request: &HttpRequest) -> Result<HttpResponse, TransportError> {
            self.clock.store(NOW + 20, Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    /// The reply is verified at the instant it arrived, not when the request was built.
    #[test]
    fn the_reply_is_judged_at_the_instant_it_arrived() {
        let plain = reply_request();
        let clock = Arc::new(AtomicI64::new(NOW));
        let route = Route {
            route_id: ROUTE_ID.into(),
            target_uri: TARGET.into(),
            audience: audience(),
            artifact_bindings: bindings(),
            extra_headers: Vec::new(),
            expected_server_keyid: None,
            verification: ClientVerification::DelegatedRequired(
                policy(),
                Box::new(|kid: &str, slot: SignerSlot, now: i64| -> ResolverOutcome {
                    match (kid, slot) {
                        (ROOT_KID, SignerSlot::Response) if now < NOW + 10 => {
                            Some(root_actor()).into()
                        }
                        _ => None::<ResolvedActor>.into(),
                    }
                }),
                Box::new(StaticRevocationList::new()),
            ),
        };
        let proxy = ClientProxy::new(
            RouteRegistry::new().register(route),
            SigningKey::from_seed_bytes(&CLIENT_SEED),
            CLIENT_KEY_ID,
            Box::new(SlowTransport {
                response: delegated_reply(&plain),
                clock: Arc::clone(&clock),
            }),
        );
        let read_clock = || clock.load(Ordering::SeqCst);
        let err = proxy
            .handle(ROUTE_ID, &plain, &call_params(&read_clock))
            .expect_err("the reply arrived after the root's deadline");
        assert_eq!(
            err,
            ProxyError::FailedClosed(HttpProfileError::DelegationIssuerUntrusted)
        );
    }

    /// A present `params` that is not an object carries arguments the ambassador would
    /// otherwise sign away as `{}`; it is refused before anything is signed or sent.
    #[test]
    fn non_object_params_are_refused_before_anything_is_signed() {
        for params in [json!([1, 2]), json!("x")] {
            let (proxy, calls) = proxy_over(required_verification(), None, None);
            let plain =
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
            let err = proxy
                .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
                .expect_err("non-object params are refused");
            assert_eq!(err, ProxyError::MalformedRequest);
            assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing may be sent");
        }
        let (proxy, calls) = proxy_over(required_verification(), None, None);
        let plain = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        let err = proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
            .expect_err("the canned transport holds no response");
        assert!(matches!(err, ProxyError::Transport(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "absent params are sent");
    }

    /// A transport that records the request it was handed and answers with a canned reply.
    struct RecordingTransport {
        response: HttpResponse,
        seen: std::sync::Mutex<Vec<HttpRequest>>,
    }

    impl RemoteTransport for RecordingTransport {
        fn round_trip(
            &self,
            request: &HttpRequest,
        ) -> Result<HttpResponse, crate::transport::TransportError> {
            self.seen.lock().expect("lock").push(request.clone());
            Ok(self.response.clone())
        }
    }

    impl RemoteTransport for Arc<RecordingTransport> {
        fn round_trip(
            &self,
            request: &HttpRequest,
        ) -> Result<HttpResponse, crate::transport::TransportError> {
            self.as_ref().round_trip(request)
        }
    }

    fn proxy_recording(response: HttpResponse) -> (ClientProxy, Arc<RecordingTransport>) {
        let route = Route {
            route_id: ROUTE_ID.into(),
            target_uri: TARGET.into(),
            audience: audience(),
            artifact_bindings: bindings(),
            extra_headers: Vec::new(),
            expected_server_keyid: None,
            verification: required_verification(),
        };
        let transport = Arc::new(RecordingTransport {
            response,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let proxy = ClientProxy::new(
            RouteRegistry::new().register(route),
            SigningKey::from_seed_bytes(&CLIENT_SEED),
            CLIENT_KEY_ID,
            Box::new(Arc::clone(&transport)),
        );
        (proxy, transport)
    }

    /// The proxy sends exactly one request, and it is the one it signed.
    #[test]
    fn the_proxy_sends_the_one_request_it_signed() {
        let plain = reply_request();
        let (proxy, transport) = proxy_recording(delegated_reply(&plain));
        proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
            .expect("the reply to the signed request verifies");

        let seen = transport.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1, "one exchange sends one request");
        let expected = signed_for(&plain);
        let expected = expected.request();
        assert_eq!(seen[0].method, expected.method);
        assert_eq!(seen[0].headers, expected.headers);
        assert_eq!(seen[0].body, expected.body);
    }

    /// A reply is judged against the request that was sent: one signed for any other
    /// request is refused, whatever else is well-formed about it.
    #[test]
    fn a_reply_to_a_different_request_is_refused() {
        let plain = reply_request();
        let other = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write"}});
        let (proxy, _) = proxy_over(required_verification(), None, Some(delegated_reply(&other)));
        let err = proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
            .expect_err("a reply bound to another request must be refused");
        assert!(matches!(err, ProxyError::FailedClosed(_)), "{err:?}");
    }

    /// The same holds for the acknowledgement of a notification.
    #[test]
    fn an_acknowledgement_of_a_different_notification_is_refused() {
        let plain = notification();
        let other = json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}});
        let (proxy, _) = proxy_over(required_verification(), None, Some(delegated_202(&other)));
        let err = proxy
            .handle(ROUTE_ID, &plain, &call_params(&|| NOW))
            .expect_err("an acknowledgement bound to another message must be refused");
        assert!(matches!(err, ProxyError::FailedClosed(_)), "{err:?}");
    }
}
