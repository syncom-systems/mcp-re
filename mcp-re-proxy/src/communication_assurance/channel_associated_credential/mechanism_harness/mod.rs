// SPDX-License-Identifier: Apache-2.0
//! Real handshakes, for the reason `tls_listener_state::resumption_acceptance` drives them:
//! what a synthetic `Vec<Vec<u8>>` proves about association is nothing. The question is what
//! the MECHANISM associates, on each path a production relationship can take, and only a
//! handshake answers it.
//!
//! The harness sits at the authority root rather than inside one adapter because BOTH
//! children establish real relationships to measure their own proposition: the adapter asks
//! what a relationship associates, and the identity derivation asks which certificate of
//! that association an identity comes from. `pub(crate)` here grants nothing in a production
//! build — the module does not exist in one.
#![cfg(test)]

mod authority;
mod handshake;
mod leaf;
mod peers;
mod tls_config;

pub(crate) use authority::make_ca;
pub(crate) use authority::make_intermediate;
pub(crate) use handshake::handshake;
pub(crate) use leaf::make_leaf;
pub(crate) use leaf::make_short_lived_uri_leaf;
pub(crate) use leaf::make_uri_leaf;
pub(crate) use peers::mutually_authenticated_peers;
pub(crate) use peers::short_lived_peers;
pub(crate) use tls_config::client_config;
pub(crate) use tls_config::server_config;
