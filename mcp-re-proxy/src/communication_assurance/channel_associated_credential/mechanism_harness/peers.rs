// SPDX-License-Identifier: Apache-2.0
//! A mutually authenticated client and server, ready to handshake.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;

use super::authority::make_ca;
use super::leaf::dns_leaf;
use super::leaf::Validity;
use super::tls_config::client_config;
use super::tls_config::server_config;

pub(crate) struct Peers {
    pub(crate) client: Arc<ClientConfig>,
    pub(crate) server: Arc<ServerConfig>,
    pub(crate) client_leaf: CertificateDer<'static>,
}

fn peers_with(validity: Validity) -> Peers {
    let client_ca = make_ca("peer-client-ca");
    let server_ca = make_ca("peer-server-ca");
    let (server_leaf, server_key) = dns_leaf(&server_ca, "localhost", false, validity);
    let (client_leaf, client_key) = dns_leaf(&client_ca, "client", true, validity);
    let server = server_config(&[client_ca.der()], vec![server_leaf], server_key);
    let client = client_config(
        &server_ca.der(),
        Some((vec![client_leaf.clone()], client_key)),
    );
    Peers {
        client,
        server,
        client_leaf,
    }
}

/// [`mutually_authenticated_peers`] with both leaves valid around the present moment.
pub(crate) fn short_lived_peers() -> Peers {
    peers_with(Validity::ShortLived)
}

pub(crate) fn mutually_authenticated_peers() -> Peers {
    peers_with(Validity::Default)
}
