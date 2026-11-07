// SPDX-License-Identifier: Apache-2.0
//! The command line of the generator.

pub(super) struct Args {
    pub(super) target: String,
    pub(super) connections: usize,
    pub(super) requests: usize,
    pub(super) mode: String,
    pub(super) client_cert: String,
    pub(super) client_key: String,
    pub(super) server_ca: String,
    pub(super) out: Option<String>,
    pub(super) id: String,
    /// Replaces the per-process nonce salt, so a second run re-sends the first run's
    /// nonces. Only the replay smoke sets it; a measured run must never.
    pub(super) nonce_salt: Option<String>,
    /// Alters one byte of each signed body after signing, so every request must be
    /// refused. Only the negative smoke sets it.
    pub(super) tamper: bool,
}

impl Args {
    /// Whether connections are held open between requests.
    pub(super) fn keep_alive(&self) -> bool {
        self.mode == "keepalive"
    }
}

pub(super) fn args() -> Args {
    let mut a = Args {
        target: String::new(),
        connections: 128,
        requests: 20000,
        mode: "keepalive".into(),
        client_cert: String::new(),
        client_key: String::new(),
        server_ca: String::new(),
        out: None,
        id: "gen0".into(),
        nonce_salt: None,
        tamper: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--target" => a.target = val(),
            "--connections" => a.connections = val().parse().expect("connections"),
            "--requests" => a.requests = val().parse().expect("requests"),
            "--mode" => a.mode = val(),
            "--client-cert" => a.client_cert = val(),
            "--client-key" => a.client_key = val(),
            "--server-ca" => a.server_ca = val(),
            "--out" => a.out = Some(val()),
            "--id" => a.id = val(),
            "--nonce-salt" => a.nonce_salt = Some(val()),
            "--tamper" => a.tamper = true,
            other => panic!("unknown flag {other}"),
        }
    }
    assert!(!a.target.is_empty(), "--target is required");
    assert!(!a.server_ca.is_empty(), "--server-ca is required");
    a
}
