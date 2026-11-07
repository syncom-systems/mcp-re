// SPDX-License-Identifier: Apache-2.0
//! The proxy tier: the argument vector it is spawned with and the serving address it
//! reports on stderr.

use std::io::BufRead;
use std::io::BufReader;
use std::process::ChildStderr;
use std::process::Command;
use std::process::Stdio;

use super::material::Material;
use super::material::MAX_CLIENT_CERT_LIFETIME_SECS;
use super::proc::guard;
use super::proc::Proc;

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const TRUST_DOMAIN: &str = "example.org";
const TARGET_URI: &str = "https://localhost/";

/// What one spawned proxy is configured with. `headroom` is both the connection and the
/// in-flight ceiling.
pub(super) struct ProxySpec<'a> {
    pub(super) cores: usize,
    pub(super) redis: &'a str,
    pub(super) inner: &'a str,
    pub(super) tier: &'a str,
    pub(super) headroom: usize,
}

fn flags(pairs: &[(&str, &str)]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|(flag, value)| [(*flag).to_string(), (*value).to_string()])
        .collect()
}

fn path_str(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

fn identity_args() -> Vec<String> {
    flags(&[
        ("--audience", AUDIENCE),
        ("--server-signer", SERVER),
        ("--server-key-id", SERVER_KEY_ID),
        ("--delegated-trust-epoch", "epoch-1"),
        ("--key-source", "file"),
    ])
}

fn material_args(m: &Material) -> Vec<String> {
    flags(&[
        ("--signing-key-seed", &path_str(&m.seed)),
        ("--tls-cert", &path_str(&m.server_cert)),
        ("--tls-key", &path_str(&m.server_key)),
        ("--client-ca", &path_str(&m.client_ca)),
        ("--trust", &path_str(&m.trust)),
    ])
}

fn admission_args() -> Vec<String> {
    flags(&[
        ("--target-uri", TARGET_URI),
        ("--mcp-protocol-version", "2026-07-28"),
        ("--trust-domain", TRUST_DOMAIN),
        ("--transport-binding", "exact"),
        ("--transport-identity-source", "uri_san"),
        (
            "--max-client-cert-lifetime",
            &MAX_CLIENT_CERT_LIFETIME_SECS.to_string(),
        ),
    ])
}

fn topology_args(spec: &ProxySpec) -> Vec<String> {
    // The second topology axis. Read from the environment rather than a flag so
    // `runtime_topology_sweep.sh` can drive it without every rig caller growing an
    // argument it does not use.
    let workers = std::env::var("MCP_RE_SAT_WORKERS_PER_SHARD").unwrap_or_else(|_| "0".into());
    flags(&[
        ("--replay-redis-url", spec.redis),
        ("--replay-durability-tier", spec.tier),
        ("--cores", &spec.cores.to_string()),
        ("--workers-per-shard", &workers),
    ])
}

fn capacity_args(spec: &ProxySpec) -> Vec<String> {
    let headroom = spec.headroom.to_string();
    // Headroom, so a shed connection never masquerades as a throughput ceiling.
    // The rig measures how fast the proxy serves, not where it starts refusing —
    // that is admission control and it has its own tests.
    flags(&[
        ("--max-connections", &headroom),
        ("--max-in-flight", &headroom),
        ("--inner-http-url", &format!("http://{}/mcp", spec.inner)),
    ])
}

fn proxy_args(m: &Material, spec: &ProxySpec) -> Vec<String> {
    let mut args = flags(&[("--bind", "127.0.0.1:0")]);
    args.push("--allow-example-fixtures".to_string());
    args.extend(identity_args());
    args.extend(material_args(m));
    args.extend(admission_args());
    args.extend(topology_args(spec));
    args.extend(capacity_args(spec));
    args
}

/// The serving address on a proxy stderr line, if the line announces one.
fn announced_addr(line: &str) -> Option<String> {
    let rest = line.split("async fleet serving on ").nth(1)?;
    // FIRST token only: the line continues with the core count and posture, and
    // trimming the whole tail yields a "host:port ..." that fails to parse.
    rest.split_whitespace().next().map(str::to_string)
}

/// Read the proxy's stderr until it names its serving address. Returns the address, if
/// one was named, and the lines seen before it.
fn read_serving_addr(reader: &mut BufReader<ChildStderr>) -> (Option<String>, Vec<String>) {
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..400 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let addr = announced_addr(&line);
        if addr.is_some() {
            return (addr, seen);
        }
        seen.push(line.trim_end().to_string());
    }
    (None, seen)
}

pub(super) fn spawn_proxy(cli: &str, m: &Material, spec: &ProxySpec) -> (Proc, String) {
    let mut child = Command::new(cli)
        .args(proxy_args(m, spec))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");

    let stderr = child.stderr.take().expect("proxy stderr");
    let mut reader = BufReader::new(stderr);
    let (addr, seen) = read_serving_addr(&mut reader);
    // Drain the rest so a full pipe never blocks the proxy mid-measurement.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    let addr = addr.unwrap_or_else(|| {
        panic!(
            "proxy never reported a serving address; its stderr was:\n{}",
            seen.join("\n")
        )
    });
    (guard(child), addr)
}
