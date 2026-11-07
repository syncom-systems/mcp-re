// SPDX-License-Identifier: Apache-2.0
//! Reading one HTTP response far enough to know it was served.
//!
//! Content-Length only — the proxy always sets it, and chunked parsing here would measure
//! the client.

use tokio::io::AsyncReadExt;

/// Whether a 2xx reply must additionally prove it came from the inner backend.
///
/// Set by the rig's `--smoke` liveness mode only. A measured run leaves it off, so the
/// hot path is byte-for-byte what it was and the quantity being measured is unchanged.
///
/// This replaces an earlier `backend_cpu > 0` assertion in the rig, which read
/// `ps -o time=`: macOS reports centiseconds (`0:00.01`) and Linux whole seconds
/// (`00:00:00`), so a healthy sub-second backend measured 0.00 on Linux and failed a
/// gate that passed locally. Dispatch is a semantic fact; it should not be inferred from
/// a host's CPU-clock granularity.
fn require_backend_echo() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| std::env::var("MCP_RE_SAT_REQUIRE_ECHO").is_ok())
}

/// A response being read off `stream` into `buf`.
struct Reply<'a, S> {
    stream: &'a mut S,
    buf: &'a mut Vec<u8>,
    tmp: [u8; 8192],
}

pub(super) async fn read_response(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(), String> {
    buf.clear();
    let mut reply = Reply {
        stream,
        buf,
        tmp: [0u8; 8192],
    };
    let head_end = reply.read_head().await?;
    let head = String::from_utf8_lossy(&reply.buf[..head_end]).to_ascii_lowercase();
    // A READABLE response is not a SERVED one. This used to count any parseable reply as
    // a success, so a proxy rejecting every request at the replay tier reported zero
    // failures and a healthy rate — while serving nothing. A rejection is cheaper than a
    // real request (no backend dispatch, no response signature), so counting it inflates
    // throughput precisely when the run is least valid.
    if !is_success(&head) {
        return Err(reply.describe_refusal(&head, head_end).await);
    }
    let Some(len) = content_length(&head) else {
        return Err(format!(
            "no parseable content-length in: {:?}",
            &head[..head.len().min(300)]
        ));
    };
    reply.read_body(head_end + len).await?;
    if require_backend_echo() {
        reply.expect_backend_echo(head_end, len)?;
    }
    Ok(())
}

impl<S: AsyncReadExt + Unpin> Reply<'_, S> {
    /// Append the next chunk off the wire to the buffer; `0` means end of stream.
    async fn fill(&mut self) -> Result<usize, String> {
        let n = self
            .stream
            .read(&mut self.tmp)
            .await
            .map_err(|e| format!("io {e}"))?;
        self.buf.extend_from_slice(&self.tmp[..n]);
        Ok(n)
    }

    /// Read until the blank line that ends the headers; the offset just past it.
    async fn read_head(&mut self) -> Result<usize, String> {
        loop {
            if self.fill().await? == 0 {
                return Err(format!(
                    "eof before headers ({} bytes: {:?})",
                    self.buf.len(),
                    String::from_utf8_lossy(&self.buf[..self.buf.len().min(200)])
                ));
            }
            if let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(p + 4);
            }
            if self.buf.len() > 1 << 20 {
                return Err("headers exceeded 1 MiB".into());
            }
        }
    }

    /// Read until the buffer holds `target` bytes.
    async fn read_body(&mut self, target: usize) -> Result<(), String> {
        while self.buf.len() < target {
            if self.fill().await? == 0 {
                return Err("eof mid-body".into());
            }
        }
        Ok(())
    }

    /// The status line alone cannot name the admission stage that refused. The proxy's
    /// fail-closed reply carries the authoritative `mcp_re_error.wire_code` in its body,
    /// so read the body (bounded) and report it: a refusal the rig cannot attribute is
    /// indistinguishable from a rig that is simply broken.
    async fn describe_refusal(&mut self, head: &str, head_end: usize) -> String {
        let status_line = head.lines().next().unwrap_or("(no status line)");
        let cap = content_length(head).unwrap_or(0).min(2048);
        while self.buf.len() < head_end + cap {
            // A read error ends the body early; the refusal is reported with what arrived.
            if self.fill().await.unwrap_or(0) == 0 {
                break;
            }
        }
        let end = self.buf.len().min(head_end + cap);
        let body = String::from_utf8_lossy(&self.buf[head_end..end]);
        format!("non-2xx response: {status_line} body={body}")
    }

    /// Liveness only, and never on a measured run: prove the reply came FROM the inner
    /// backend rather than from the proxy alone. The backend echoes the request's
    /// JSON-RPC method into `result.echo`, so its presence is dispatch evidence that
    /// does not depend on any host's CPU accounting.
    fn expect_backend_echo(&self, head_end: usize, len: usize) -> Result<(), String> {
        let end = self.buf.len().min(head_end + len);
        let body = String::from_utf8_lossy(&self.buf[head_end..end]);
        if body.contains("\"echo\"") {
            return Ok(());
        }
        Err(format!(
            "2xx reply carries no backend echo — nothing was dispatched to the inner \
             server; body={}",
            &body[..body.len().min(512)]
        ))
    }
}

fn is_success(head: &str) -> bool {
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|c| (200..300).contains(&c))
}

fn content_length(head: &str) -> Option<usize> {
    head.split("content-length:")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .and_then(|v| v.trim().parse::<usize>().ok())
}
