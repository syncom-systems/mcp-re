// SPDX-License-Identifier: Apache-2.0
//! The HTTP transport of the proof: POST a signed request, read the answer back as the
//! profile's `HttpResponse`.

use std::io::Read;

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

/// The agent every leg POSTs through: statuses are data, and no proxy is consulted.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .new_agent()
}

/// POST the signed request, returning the response as an `HttpResponse` for BOTH
/// success and error statuses (a rejection is a 4xx/5xx the profile still signs).
pub fn post(agent: &ureq::Agent, url: &str, request: &HttpRequest) -> HttpResponse {
    let mut r = agent.post(url);
    for (k, v) in &request.headers {
        r = r.header(k, v);
    }
    match r.send(&request.body[..]) {
        Ok(resp) => read_response(resp),
        Err(e) => panic!("transport error to {url}: {e}"),
    }
}

/// Reconstruct the profile `HttpResponse` from a ureq response. Header names +
/// values are read BEFORE consuming the body reader.
fn read_response(resp: ureq::http::Response<ureq::Body>) -> HttpResponse {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(name, v)| v.to_str().ok().map(|v| (name.to_string(), v.to_owned())))
        .collect();
    let mut body = Vec::new();
    resp.into_body()
        .into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .expect("read response body");
    HttpResponse {
        status,
        headers,
        body,
    }
}
