// SPDX-License-Identifier: Apache-2.0
//! Server and client configurations for the handshake controls.

use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::ring;
use rustls::server::WebPkiClientVerifier;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;

/// The production client-auth posture: a `WebPkiClientVerifier` over the anchors, with
/// a session store so a second connection can resume. The verifier is what makes
/// *established with no credential* unreachable, so the control must use it rather
/// than a permissive stand-in.
pub(crate) fn server_config(
    anchors: &[CertificateDer<'static>],
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    for anchor in anchors {
        roots.add(anchor.clone()).expect("anchor");
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("client verifier");
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .expect("server cert");
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(64);
    config.max_early_data_size = 0;
    Arc::new(config)
}

pub(crate) fn client_config(
    server_ca: &CertificateDer<'static>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Arc<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(server_ca.clone()).expect("server ca");
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots);
    let mut config = match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client cert"),
        None => builder.with_no_client_auth(),
    };
    // Without a client-side cache no second connection can offer a ticket, and the
    // resumed-path control would silently be a second full handshake.
    config.resumption = Resumption::in_memory_sessions(16);
    Arc::new(config)
}
