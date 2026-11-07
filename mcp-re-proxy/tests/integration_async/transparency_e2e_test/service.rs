// SPDX-License-Identifier: Apache-2.0
//! A hermetic transparency service on a loopback socket.
//!
//! It is not a canned-response table. It parses the Signed Statement it is sent,
//! registers it in a real RFC 9162 log, and answers with a real RFC 9942 receipt about
//! those exact bytes.

use super::fixtures::{sign_with, ts_key, TS_KID};
use base64::Engine;
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;

/// How the hermetic service answers a submission.
#[derive(Clone, Copy)]
pub(super) enum ServiceMode {
    /// SCRAPI, `201 Created` with the receipt in the body.
    Synchronous,
    /// SCRAPI, `202 Accepted` + `Location`, then `n` × `204`, then `200` with the receipt.
    Asynchronous { pending: u32 },
    /// The `capsule-anchor` contract: `200` with JSON `{"receipt_b64": …}`, no polling.
    ///
    /// A separate mode rather than a status variation, because the difference is the whole
    /// reason there is a second mechanism leaf: a different resource, a different request
    /// media type, and the receipt arriving base64 inside JSON rather than as the body.
    CapsuleAnchor,
}

impl ServiceMode {
    /// The `--registration-protocol` token an operator names for this service.
    pub(super) fn protocol(self) -> &'static str {
        match self {
            ServiceMode::Synchronous | ServiceMode::Asynchronous { .. } => "scrapi-11",
            ServiceMode::CapsuleAnchor => "capsule-anchor",
        }
    }

    fn polls_before_the_receipt(self) -> u32 {
        match self {
            ServiceMode::Asynchronous { pending } => pending,
            ServiceMode::Synchronous | ServiceMode::CapsuleAnchor => 0,
        }
    }
}

/// One HTTP request as the service read it off the socket.
struct Request {
    raw: Vec<u8>,
    text: String,
    head_end: usize,
}

impl Request {
    fn parse(raw: Vec<u8>) -> Self {
        let text = String::from_utf8_lossy(&raw).to_string();
        let head_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
        Request {
            raw,
            text,
            head_end,
        }
    }

    fn is_post(&self) -> bool {
        self.text.starts_with("POST ")
    }

    fn body(&self) -> &[u8] {
        &self.raw[self.head_end..]
    }
}

/// Whether `raw` holds the complete headers and the body they declare.
fn is_complete(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw).to_string();
    let Some(head_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let declared: usize = text
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    raw.len() >= head_end + 4 + declared
}

/// Read until the headers are complete, then the declared body. `None` when the socket
/// errors.
fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if is_complete(&raw) {
            break;
        }
    }
    Some(Request::parse(raw))
}

/// The two contracts put the statement in different places, and the service reads it the
/// way the contract it is speaking says to. Accepting either shape on either path would
/// let a mechanism pass this lane while sending the other one's request.
fn submitted_statement(mode: ServiceMode, request: &Request) -> Vec<u8> {
    match mode {
        ServiceMode::CapsuleAnchor => {
            assert!(
                request
                    .text
                    .starts_with("POST /transparency/register-statement "),
                "the capsule-anchor leaf must POST that contract's resource: {}",
                request.text.lines().next().unwrap_or_default(),
            );
            let body: serde_json::Value = serde_json::from_slice(request.body())
                .expect("the capsule-anchor leaf submits JSON");
            base64::engine::general_purpose::STANDARD
                .decode(
                    body["signed_statement_b64"]
                        .as_str()
                        .expect("signed_statement_b64"),
                )
                .expect("standard base64")
        }
        ServiceMode::Synchronous | ServiceMode::Asynchronous { .. } => request.body().to_vec(),
    }
}

/// A `capsule-anchor` `200`: the receipt base64 inside this contract's JSON, beside the
/// unsigned log coordinates the leaf must NOT consume.
fn http_json_receipt(receipt: &[u8]) -> Vec<u8> {
    let body = serde_json::to_vec(&serde_json::json!({
        "receipt_b64": base64::engine::general_purpose::STANDARD.encode(receipt),
        "entry_hash": "unused-by-the-leaf",
        "entry_hash_scheme": "sig_structure",
        "leaf_index": 0,
        "tree_size": 1,
    }))
    .expect("json");
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

/// An HTTP response carrying COSE bytes.
fn http_cose(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = if status == 201 { "Created" } else { "OK" };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cose\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// What the service says next, and whether that hands the receipt over.
struct Answer {
    response: Vec<u8>,
    delivered: bool,
}

/// The service's state across the exchanges one registration needs.
struct Service {
    mode: ServiceMode,
    operation: String,
    pending: u32,
    receipt: Vec<u8>,
}

impl Service {
    fn answer(&mut self, request: &Request) -> Answer {
        if request.is_post() {
            self.answer_submission(request)
        } else if self.pending > 0 {
            self.pending -= 1;
            Answer {
                response:
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_vec(),
                delivered: false,
            }
        } else {
            Answer {
                response: http_cose(200, &self.receipt),
                delivered: true,
            }
        }
    }

    fn answer_submission(&mut self, request: &Request) -> Answer {
        let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(
            &submitted_statement(self.mode, request),
        )
        .expect("the auditor submits a Signed Statement");
        let mut log = PrototypeTransparencyService::new(TS_KID);
        self.receipt = log
            .register(&statement, sign_with(ts_key()))
            .expect("the log registers it")
            .to_cose()
            .to_vec();
        match self.mode {
            ServiceMode::CapsuleAnchor => Answer {
                response: http_json_receipt(&self.receipt),
                delivered: true,
            },
            ServiceMode::Synchronous => Answer {
                response: http_cose(201, &self.receipt),
                delivered: true,
            },
            ServiceMode::Asynchronous { .. } => Answer {
                response: format!(
                    "HTTP/1.1 202 Accepted\r\nLocation: {}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n",
                    self.operation
                )
                .into_bytes(),
                delivered: false,
            },
        }
    }

    /// Serve exchanges until the receipt has been handed over, and not before: a loop that
    /// ended when the pending count reached zero would close on the poll BEFORE the one
    /// that answers.
    fn serve(mut self, listener: TcpListener) {
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_request(&mut stream) else {
                return;
            };
            let answer = self.answer(&request);
            let _ = stream.write_all(&answer.response);
            let _ = stream.flush();
            if answer.delivered {
                return;
            }
        }
    }
}

/// A transparency service on a loopback socket, speaking the registration exchange.
///
/// Returns the base URL and a join handle. It serves exactly the exchanges one
/// registration needs and then stops.
pub(super) fn spawn_transparency_service(
    mode: ServiceMode,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the service");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let service = Service {
        mode,
        operation: format!("{base}/operations/1"),
        pending: mode.polls_before_the_receipt(),
        receipt: Vec::new(),
    };
    let handle = std::thread::spawn(move || service.serve(listener));
    (base, handle)
}
