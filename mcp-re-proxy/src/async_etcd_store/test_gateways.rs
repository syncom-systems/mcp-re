#![cfg(test)]
//! Scripted etcd JSON gateways on local sockets for the store's tests: the store holds a
//! concrete `hyper` client rather than an injectable transport, so its behaviour is proven
//! against real listeners — one that never answers, one that counts what it is asked, and
//! one whose every reply a test chooses.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

/// How a scripted gateway answers one request: from its path and JSON body, the full
/// HTTP response text.
pub(super) type Answer = Arc<dyn Fn(&str, &Value) -> String + Send + Sync>;

async fn bind() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    (listener, format!("http://{addr}"))
}

/// A listener that accepts connections, counts them, and never replies — the
/// black-holed gateway an operator actually meets (a dropped route, a firewall that
/// discards rather than resets). Returns its address and the accept counter.
pub(super) async fn silent_gateway() -> (String, Arc<AtomicUsize>) {
    let (listener, base) = bind().await;
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            // Hold the connection open and answer nothing. Dropping it would send a FIN
            // and produce a transport error instead of a hang.
            counter.fetch_add(1, Ordering::SeqCst);
            std::mem::forget(stream);
        }
    });
    (base, accepts)
}

/// The value of the `content-length` header in a request head, or 0.
fn declared_body_len(request: &str) -> usize {
    request
        .to_ascii_lowercase()
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Read one whole request from `stream`: its path and JSON body. `None` when the peer
/// closes or errors before a whole request has arrived.
async fn read_request(stream: &mut TcpStream) -> Option<(String, Value)> {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        seen.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&seen).to_string();
        let Some(head_len) = text.find("\r\n\r\n") else {
            continue;
        };
        if seen.len() < head_len + 4 + declared_body_len(&text) {
            continue;
        }
        let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
        let body = serde_json::from_slice(&seen[head_len + 4..]).unwrap_or_default();
        return Some((path, body));
    }
}

/// One request per connection is enough for this store's use: answer as soon as a whole
/// request has arrived.
async fn serve_one(mut stream: TcpStream, answer: Answer) {
    if let Some((path, request)) = read_request(&mut stream).await {
        let _ = stream.write_all(answer(&path, &request).as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// A gateway whose every reply is chosen by `answer`. Each connection carries one
/// request. Returns the gateway's base URL.
pub(super) async fn scripted_gateway(answer: Answer) -> String {
    let (listener, base) = bind().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_one(stream, Arc::clone(&answer)));
        }
    });
    base
}

pub(super) fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A scripted etcd JSON gateway: answers `/v3/lease/grant` with an incrementing lease id
/// and `/v3/kv/txn` with a successful compare, counting the calls to each.
pub(super) struct CountingGateway {
    pub(super) base: String,
    pub(super) grants: Arc<AtomicUsize>,
    pub(super) txns: Arc<AtomicUsize>,
    /// The `TTL` of every lease-grant request body, in arrival order.
    pub(super) ttls: Arc<Mutex<Vec<i64>>>,
}

pub(super) async fn counting_gateway() -> CountingGateway {
    let grants = Arc::new(AtomicUsize::new(0));
    let txns = Arc::new(AtomicUsize::new(0));
    let ttls = Arc::new(Mutex::new(Vec::new()));
    let (g, t, l) = (Arc::clone(&grants), Arc::clone(&txns), Arc::clone(&ttls));
    let base = scripted_gateway(Arc::new(move |path: &str, request: &Value| {
        if path != "/v3/lease/grant" {
            t.fetch_add(1, Ordering::SeqCst);
            return ok_json("{\"succeeded\":true}");
        }
        let id = g.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(ttl) = request["TTL"].as_i64() {
            l.lock().expect("ttls").push(ttl);
        }
        ok_json(&format!("{{\"ID\":\"{id}\",\"TTL\":\"300\"}}"))
    }))
    .await;
    CountingGateway {
        base,
        grants,
        txns,
        ttls,
    }
}
