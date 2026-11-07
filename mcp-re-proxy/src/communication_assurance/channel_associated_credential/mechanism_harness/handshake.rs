// SPDX-License-Identifier: Apache-2.0
//! One in-memory handshake between a client and a server configuration.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls_pki_types::ServerName;

/// The most flights the loop exchanges before giving up on a handshake that never settles.
const MAX_ROUNDS: usize = 16;

/// Whether both ends have nothing left to send and are no longer handshaking.
fn settled(client: &ClientConnection, server: &ServerConnection) -> bool {
    !client.wants_write()
        && !server.wants_write()
        && !client.is_handshaking()
        && !server.is_handshaking()
}

/// Move one flight from the client to the server. `false` when the server refused it.
fn client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) -> bool {
    let mut buf = Vec::new();
    if client.wants_write() {
        client.write_tls(&mut buf).expect("client write");
        if !buf.is_empty() {
            server.read_tls(&mut buf.as_slice()).expect("server read");
            return server.process_new_packets().is_ok();
        }
    }
    true
}

/// Move one flight from the server to the client. `false` when the client refused it.
fn server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) -> bool {
    let mut buf = Vec::new();
    if server.wants_write() {
        server.write_tls(&mut buf).expect("server write");
        if !buf.is_empty() {
            client.read_tls(&mut buf.as_slice()).expect("client read");
            return client.process_new_packets().is_ok();
        }
    }
    true
}

/// Drive one in-memory handshake and hand back the server connection, whatever state
/// it reached. Errors are not asserted here: one control's subject is a handshake that
/// FAILS, and a helper that panicked on it could not express that.
pub(crate) fn handshake(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> ServerConnection {
    let name = ServerName::try_from("localhost").expect("server name");
    let mut c = ClientConnection::new(Arc::clone(client), name).expect("client conn");
    let mut s = ServerConnection::new(Arc::clone(server)).expect("server conn");

    for _ in 0..MAX_ROUNDS {
        if !client_to_server(&mut c, &mut s) || !server_to_client(&mut s, &mut c) {
            break;
        }
        if settled(&c, &s) {
            break;
        }
    }
    s
}
