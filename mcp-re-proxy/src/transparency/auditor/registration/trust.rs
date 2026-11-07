// SPDX-License-Identifier: Apache-2.0
//! What a registration receipt is judged against.

use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::TransparencyKeyLifecycle;

/// Everything a receipt is judged against, all of it already loaded.
///
/// `issuer_key` is the key this auditor signed with, `pin` the operator's pinned service,
/// `ts_key` the lifecycle the audit profile states for a service key, and `clock` the
/// auditor's own time. Nothing here is fetched while a receipt is checked.
///
/// Declared in every flavor so `RegistrationTarget::register` has one signature; only the
/// flavor with the transport reads the fields.
#[cfg_attr(not(feature = "scitt_registration"), allow(dead_code))]
#[derive(Clone, Copy)]
pub struct RegistrationTrust<'a> {
    /// The key the registered statement was signed with.
    pub issuer_key: &'a mcp_re_core::VerificationKey,
    /// The operator's pin of the transparency service.
    pub pin: &'a ScittServiceTrustPin,
    /// The lifecycle the audit profile states for a service key, by kid.
    pub ts_key: &'a dyn Fn(&str) -> Option<TransparencyKeyLifecycle>,
    /// The auditor's current time, read when a receipt is accepted.
    pub clock: &'a dyn Fn() -> i64,
}
