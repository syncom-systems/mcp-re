// SPDX-License-Identifier: Apache-2.0
//! Inner backends under the test's control: ones that answer, and ones that report a fixed
//! outcome, refuse admission, or retire the signer mid-flight.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_inner::DispatchCompletionBound;
use mcp_re_proxy::async_inner::DispatchedOutcome;
use mcp_re_proxy::async_inner::InProcessInner;
use mcp_re_proxy::async_inner::NotAdmitted;
use mcp_re_proxy::async_inner::PreparedInnerDispatch;
use mcp_re_proxy::SigningRetirement;

/// A fixture inner still states a finite bound: the serving path refuses an UNSTATED one,
/// and a fixture declaring none would measure that refusal instead of the behaviour under
/// test.
const FIXTURE_BOUND: DispatchCompletionBound =
    DispatchCompletionBound::Within(Duration::from_secs(1));

/// An in-process backend answering every forwarded body through `respond`.
pub(super) fn answering(
    respond: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> Box<dyn AsyncInnerServer> {
    Box::new(InProcessInner::new(
        respond,
        DispatchCompletionBound::Within(Duration::ZERO),
    ))
}

/// A backend that replies with exactly `bytes`, whatever it is asked.
pub(super) fn replying_with(bytes: &[u8]) -> Box<dyn AsyncInnerServer> {
    let bytes = bytes.to_vec();
    answering(move |_: &[u8]| bytes.clone())
}

/// The JSON-RPC `id` of the forwarded request, rendered for splicing into a canned reply.
///
/// A conformant backend echoes the request's id, and since ADR-MCPRE-058 §10 (ruling D5)
/// the PEP enforces that: an answer leg carries `id: 2`, so a fixture hard-coding `id: 1`
/// is a backend answering a call nobody made. These fixtures used to do exactly that and
/// nothing noticed, which is the correlation gap the rule closes.
fn echoed_id(forwarded: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(forwarded)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
        .to_string()
}

/// A JSON-RPC success reply to `forwarded` carrying `result_json`.
fn result_reply(forwarded: &[u8], result_json: &str) -> Vec<u8> {
    let id = echoed_id(forwarded);
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result_json}}}"#).into_bytes()
}

fn complete_reply(forwarded: &[u8]) -> Vec<u8> {
    result_reply(forwarded, r#"{"resultType":"complete","confirmed":true}"#)
}

fn input_required_reply(forwarded: &[u8], request_state: &str) -> Vec<u8> {
    result_reply(
        forwarded,
        &format!(r#"{{"resultType":"input_required","requestState":"{request_state}"}}"#),
    )
}

/// The `requestState` an answer leg re-presents in its params, if any.
fn answered_state(forwarded: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(forwarded).ok()?;
    v.get("params")?
        .get("requestState")?
        .as_str()
        .map(str::to_owned)
}

/// An ELICITING inner: a first call (no `inputResponses`/`requestState`) returns an
/// `InputRequiredResult` carrying an opaque `requestState`; an answer call returns a
/// terminal result. Mirrors `tools/fastmcp_inner_backend.py`'s `confirm_action`.
pub(super) fn eliciting_inner(request_state: &'static str) -> Box<dyn AsyncInnerServer> {
    answering(move |forwarded: &[u8]| {
        let v: serde_json::Value =
            serde_json::from_slice(forwarded).unwrap_or(serde_json::Value::Null);
        let is_answer = v
            .get("params")
            .map(|p| p.get("inputResponses").is_some() || p.get("requestState").is_some())
            .unwrap_or(false);
        if is_answer {
            complete_reply(forwarded)
        } else {
            input_required_reply(forwarded, request_state)
        }
    })
}

/// An inner backend that replies to every call with `result_json` as the result member.
pub(super) fn malformed_eliciting_inner(result_json: &'static str) -> Box<dyn AsyncInnerServer> {
    answering(move |forwarded: &[u8]| result_reply(forwarded, result_json))
}

/// An inner backend that elicits TWICE: the first answer opens a second leg.
///
/// This is what an ordinary multi-step approval looks like — confirm the action, then
/// confirm a parameter of it — and it is the sequence that makes `Consumed -> Recorded`
/// reachable rather than theoretical.
pub(super) fn twice_eliciting_inner(
    first: &'static str,
    second: &'static str,
) -> Box<dyn AsyncInnerServer> {
    answering(move |forwarded: &[u8]| match answered_state(forwarded) {
        // The answer to leg 1 opens leg 2.
        Some(state) if state == first => input_required_reply(forwarded, second),
        // The answer to leg 2 completes the exchange.
        Some(_) => complete_reply(forwarded),
        // The original call opens leg 1.
        None => input_required_reply(forwarded, first),
    })
}

/// An inner backend that counts how many times it was actually invoked.
pub(super) fn counting_inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
    answering(move |forwarded: &[u8]| {
        calls.fetch_add(1, Ordering::SeqCst);
        result_reply(forwarded, r#"{"resultType":"complete","ok":true}"#)
    })
}

/// A fresh invocation counter, and how many invocations it has recorded.
pub(super) fn counter() -> Arc<AtomicUsize> {
    Arc::new(AtomicUsize::new(0))
}

pub(super) fn invocations(calls: &AtomicUsize) -> usize {
    calls.load(Ordering::SeqCst)
}

/// An inner plane that admits, then reports a fixed outcome without transmitting anything
/// the test can observe.
struct FixedOutcomeInner(DispatchedOutcome);

impl AsyncInnerServer for FixedOutcomeInner {
    fn prepare<'a>(&'a self, _request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        let outcome = self.0.clone();
        Ok(PreparedInnerDispatch::over(
            move || Box::pin(async move { outcome }),
            FIXTURE_BOUND,
        ))
    }
}

/// An inner plane that reports `outcome` from a committed dispatch.
pub(super) fn reporting(outcome: DispatchedOutcome) -> Box<dyn AsyncInnerServer> {
    Box::new(FixedOutcomeInner(outcome))
}

/// An inner plane that refuses to admit anything, and never transmits.
struct RefusingInner(&'static str);

impl AsyncInnerServer for RefusingInner {
    fn prepare<'a>(&'a self, _request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        Err(NotAdmitted(self.0))
    }
}

/// An inner plane that declines admission for `reason`.
pub(super) fn refusing(reason: &'static str) -> Box<dyn AsyncInnerServer> {
    Box::new(RefusingInner(reason))
}

/// An inner plane that retires the delegated signer mid-flight, then fails the dispatch.
struct SignerRetiringInner(SigningRetirement);

impl AsyncInnerServer for SignerRetiringInner {
    fn prepare<'a>(&'a self, _request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        let retirement = self.0.clone();
        Ok(PreparedInnerDispatch::over(
            move || {
                // At the DISPATCH, not at the preparation: the point of the fixture is a
                // signer that goes away while the exchange is past its threshold.
                retirement.retire_permanently();
                Box::pin(async { DispatchedOutcome::Indeterminate("inner request timed out") })
            },
            FIXTURE_BOUND,
        ))
    }
}

pub(super) fn signer_retiring(retirement: SigningRetirement) -> Box<dyn AsyncInnerServer> {
    Box::new(SignerRetiringInner(retirement))
}
