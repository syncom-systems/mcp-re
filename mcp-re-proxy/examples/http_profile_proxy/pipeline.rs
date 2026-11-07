//! One request through the full HTTP-profile pipeline.
//!
//! Always yields a hyper response — a signed reply on success, a signed rejection receipt
//! on any fail-closed step. Each stage returns `Err(receipt)` to stop the pipeline.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::Request;
use hyper::Response;

use mcp_re_core::McpReError;
use mcp_re_http_profile::result_class::input_required_state;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_proxy::async_inner::AsyncInnerServer;

use crate::body::is_notification;
use crate::body::strip_top_level_meta;
use crate::hpp_common;
use crate::receipts::rejection;
use crate::receipts::to_hyper;
use crate::receipts::Verified;
use crate::ProxyState;

/// One request through the pipeline, as a hyper response.
pub(super) async fn handle(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = serve(&state, req).await.unwrap_or_else(|receipt| receipt);
    Ok(to_hyper(response))
}

async fn serve(state: &ProxyState, req: Request<Incoming>) -> Result<HttpResponse, HttpResponse> {
    let http_req = read_request(req).await?;
    let now = hpp_common::now_unix();
    let audience = hpp_common::audience();
    let verified = verify(&http_req, &audience, now)?;
    let admitted = Admitted {
        state,
        receipt: Verified {
            request: &http_req,
            verified: &verified,
        },
        audience_id: &audience.audience_id,
        now,
    };
    admitted.run().await
}

/// Reconstruct the `HttpRequest` (method, `@target-uri`, headers, body).
async fn read_request(req: Request<Incoming>) -> Result<HttpRequest, HttpResponse> {
    let method = req.method().as_str().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let Ok(collected) = req.into_body().collect().await else {
        return Err(rejection(
            None,
            None,
            McpReError::SerializationFailed.wire_code(),
            400,
        ));
    };
    // The canonical @target-uri both sides sign over (deployment-configured).
    Ok(HttpRequest {
        method,
        target_uri: hpp_common::target(),
        headers,
        body: collected.to_bytes().to_vec(),
    })
}

/// Step 2 — verify (RFC 9421 + 9530 + evidence block).
fn verify(
    http_req: &HttpRequest,
    audience: &AudienceTuple,
    now: i64,
) -> Result<VerifiedMcpRequest, HttpResponse> {
    let resolver = hpp_common::resolver();
    // The proof request carries no artifact bindings, so no credential material is
    // needed; a binding with no obtainable credential still fails closed.
    let no_material = |_b: &ArtifactBinding| None;
    Verifier::new(&VerifierPolicy::default(), &resolver)
        .verify_request(http_req, audience, &no_material, now)
        .map_err(|e| {
            eprintln!("reject: verify_request_full -> {}", e.wire_code());
            // The request never verified: nothing to bind the receipt to.
            rejection(Some(http_req), None, e.wire_code(), 403)
        })
}

/// A request that verified, with what the remaining stages share.
struct Admitted<'a> {
    state: &'a ProxyState,
    receipt: Verified<'a>,
    audience_id: &'a str,
    now: i64,
}

impl Admitted<'_> {
    /// Steps 3 to 6, in order.
    async fn run(&self) -> Result<HttpResponse, HttpResponse> {
        self.admit().await?;
        let inner_bytes = self.forward().await;
        if is_notification(&self.receipt.request.body) {
            return self.acknowledge();
        }
        self.sign_reply(inner_bytes).await
    }

    /// Steps 3a, 3 and 3b — continuation prep, replay admission, continuation retirement.
    ///
    /// A verified request carrying a continuation is an ANSWER leg: the plane reads the open
    /// leg's retained evidence without spending it (ADR-MCPS-047), keyed by the actor the
    /// VERIFIER resolved and the `requestState` the client re-presents. A store that did not
    /// answer is refused as this deployment's fault, never as the caller's forged
    /// continuation.
    ///
    /// Replay admission is fail-closed through the configured tier, on the entry point the
    /// shipped serving path awaits: a shared Redis tier detects a replay across ALL
    /// replicas; the fleet-strict gate refuses a sub-minimum tier, and a store that
    /// self-reports the single-process class, before the store is touched. A continuation,
    /// when present, is verified there against the retained handles before the nonce is
    /// burned, and the awaited atomic admission is the last step.
    ///
    /// The answer leg is then admitted, so its continuation retires NOW, before the backend
    /// runs. Of two concurrent answer legs that both bound successfully, exactly one retires
    /// the approval; the other, and a tier that did not answer the spend, are refused with
    /// the classification the plane states for each.
    async fn admit(&self) -> Result<(), HttpResponse> {
        let receipt = &self.receipt;
        let prep = self
            .state
            .continuations
            .read_answer(receipt.verified, &receipt.request.body, self.audience_id)
            .await
            .map_err(|refusal| receipt.reject_continuation(refusal))?;
        // Verified, then refused by replay admission: the receipt binds to its evidence.
        self.state
            .replay
            .admit(receipt.verified, prep.binding(), self.now)
            .await
            .map_err(|e| receipt.reject(e.wire_code(), 409))?;
        match self.state.continuations.retire(prep).await.refusal() {
            Some(refusal) => Err(receipt.reject_continuation(refusal)),
            None => Ok(()),
        }
    }

    /// Step 4 — strip the proxy-owned top-level `_meta` (the request evidence block) so the
    /// backend sees clean MCP, then forward through the real inner pool. Preparing takes the
    /// plane's capacity and transmits nothing; dispatching consumes it and never errors: a
    /// dead/hostile backend yields a synthesized inner-unavailable response, which we STILL
    /// sign (fail-closed, never a silent allow).
    async fn forward(&self) -> Vec<u8> {
        let forwarded = strip_top_level_meta(&self.receipt.request.body);
        let prepared = match self.state.inner.prepare(&forwarded) {
            Ok(prepared) => prepared,
            Err(why) => panic!("the example's inner plane refused to prepare: {why:?}"),
        };
        // The example wires an in-process closure inner, which has no transport to fail and
        // so only ever reports `Replied`. The production path classifies all three
        // post-commitment outcomes; here anything else would be a bug in the seam, not a
        // case this demo can exercise.
        match prepared.dispatch().await {
            mcp_re_proxy::async_inner::DispatchedOutcome::Replied(bytes) => bytes,
            other => panic!("the example's in-process inner cannot report {other:?}"),
        }
    }

    /// Step 4a — a one-way NOTIFICATION (a JSON-RPC message with no `id`) earns a signed
    /// bodyless 202, not a bodied reply (#424 / #418), exactly as the production serving
    /// path does it. The backend already received it; the 202 states only that the
    /// enforcement boundary authenticated and accepted the message, NOT that any action
    /// completed. Without this the notification fell through to the bodied signer, which
    /// had no reply to sign and refused the exchange the SDKs are proved against.
    fn acknowledge(&self) -> Result<HttpResponse, HttpResponse> {
        sign_delegated_accepted_202(self.receipt.request, &hpp_common::signing_window(self.now))
            .map_err(|e| self.receipt.reject(e.wire_code(), 500))
    }

    /// Step 5 — sign the backend reply, bound to THIS request.
    ///
    /// The DELEGATED signer signs; the root only vouches for it via the credential the
    /// response carries (ADR-MCPRE-052). The root key never touches a response, and the
    /// verifier enrols only the root — it learns the delegated key from the credential.
    async fn sign_reply(&self, inner_bytes: Vec<u8>) -> Result<HttpResponse, HttpResponse> {
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: inner_bytes,
        };
        let response_base = sign_delegated_response_full(
            &mut response,
            self.receipt.request,
            &hpp_common::signing_window(self.now),
        )
        .map_err(|e| self.receipt.reject(e.wire_code(), 500))?;
        self.record_open_leg(&response, response_base).await?;
        Ok(response)
    }

    /// Step 6 — MRTR open-leg record (ADR-MCPS-047). When the signed reply is an
    /// `InputRequiredResult`, retain evidence handles over the two signature bases a later
    /// answer leg must bind to: THIS request's, and the reply's just produced. A reply that
    /// cannot be classified is refused rather than signed away as terminal (MCPRE-495); a
    /// continuation that cannot be recorded is refused rather than returned unanswerable.
    async fn record_open_leg(
        &self,
        response: &HttpResponse,
        response_base: Vec<u8>,
    ) -> Result<(), HttpResponse> {
        let receipt = &self.receipt;
        let open_leg_state =
            input_required_state(&response.body).map_err(|e| receipt.reject(e.wire_code(), 502))?;
        let Some(request_state) = open_leg_state else {
            return Ok(());
        };
        self.state
            .continuations
            .record_open(
                receipt.verified,
                self.audience_id,
                &request_state,
                response_base,
            )
            .await
            .map_err(|refusal| receipt.reject_continuation(refusal))
    }
}
