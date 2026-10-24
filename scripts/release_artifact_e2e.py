#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Signed-call acceptance check for a released installation.

    plain MCP client -> mcp-re-client (release archive) -> TLS tap -> mcp-re-proxy (published
    image, deploy/compose) -> Streamable-HTTP MCP backend (tools/fastmcp_inner_backend.py)

Everything is a separate process and every hop is a real socket. The only thing this script
owns is the tap, which is the one place a signed request can be modified or recorded on its
way to the proxy; it terminates the client's mTLS and re-originates it with the evaluation
client certificate, so the proxy sees the same transport identity the client presented.

It establishes, against the artifacts rather than the source tree:

  1. a signed call is admitted, and the backend receives exactly it;
  2. a call modified in flight is refused, and the backend receives nothing;
  3. a recorded call replayed to the proxy is refused, and the backend receives nothing;
  4. the same refusal holds after the proxy restarts, and after Redis restarts (the replay
     authority is the Redis append-only volume, not proxy memory);
  5. the installation still serves a fresh call afterwards, so the refusals are not a dead
     service.

Source-level coverage of why each refusal holds is the Bazel suites'; this is the deployment
boundary only. Needs docker (compose), openssl, and the backend's requirements
(`mcp`, `uvicorn`, pinned in deploy/docker/Dockerfile.inner).

    scripts/release_artifact_e2e.py --client /path/to/mcp-re-client --version 0.19.0
"""

import argparse
import base64
import http.client
import json
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_SRC = ROOT / "deploy" / "compose"
# The published compose reference's own server identity (env.example) and listener
# (compose.yaml, verify.sh).
AUDIENCE = "did:web:mcp-re.example.net"
TARGET_URI = "https://mcp-re-proxy:8600/mcp"
SERVER_NAME = "mcp-re-proxy"
SERVER_KEY_ID = "server-key-1"
EPOCH = "epoch-1"
PROXY_PORT = 8600
CLIENT_KEY_ID = "evaluation-1"
ORG_KID = "acceptance-org-1"
MANIFEST_DOMAIN = b"mcp-re/trust-anchor-manifest/v1"
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {"text": "hello"}},
}


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def openssl(*args, data=None):
    return subprocess.run(
        ["openssl", *args], input=data, check=True, capture_output=True
    ).stdout


def registry_port(service):
    with open(ROOT / "config" / "ports.toml", "rb") as fh:
        return tomllib.load(fh)["services"][service]["port"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def public_key(pem_or_der, form="PEM"):
    der = openssl("pkey", "-inform", form, "-pubout", "-outform", "DER", data=pem_or_der)
    return der[-32:]


def write_secret(path, text):
    path.write_text(text)
    path.chmod(0o600)


def publish_trust(work, secrets):
    """The client's trust inputs: the proxy's signing root, named in a manifest that an
    organisation key signs, exactly as docs/client-sidecar-deployment-guide.md describes."""
    seed = base64.urlsafe_b64decode((secrets / "server" / "signing.seed").read_text().strip() + "==")
    root_pub = public_key(ED25519_PKCS8_PREFIX + seed, "DER")
    org_pem = work / "org.pem"
    openssl("genpkey", "-algorithm", "ed25519", "-out", str(org_pem))
    org_pub = public_key(org_pem.read_bytes())
    now = int(time.time())
    body = json.dumps(
        {
            "profile": "mcp-re-http-v1",
            "manifest_version": 1,
            "current_issuers": [
                {
                    "issuer_kid": SERVER_KEY_ID,
                    "public_key": b64url(root_pub),
                    "role": "server",
                    "trust_domain": SERVER_NAME,
                    "subject": AUDIENCE,
                }
            ],
            "retiring_issuers": [],
            "revoked_issuers": [],
            "issued_at": now - 100,
            "expires_at": now + 86400,
        },
        separators=(",", ":"),
    )
    kid = ORG_KID.encode()
    preimage = MANIFEST_DOMAIN + len(kid).to_bytes(8, "big") + kid + body.encode()
    pre = work / "preimage.bin"
    pre.write_bytes(preimage)
    sig = openssl("pkeyutl", "-sign", "-inkey", str(org_pem), "-rawin", "-in", str(pre))
    envelope = f'{{"manifest":{body},"signer_kid":"{ORG_KID}","signature":"{b64url(sig)}"}}'
    (work / "trust-anchors.json").write_text(envelope)
    return b64url(org_pub)


def write_client_config(work, secrets, client_port, tap_port, org_pub):
    der = openssl("pkey", "-in", str(secrets / "client" / "client-signing.key"), "-outform", "DER")
    write_secret(work / "client.seed", b64url(der[-32:]))
    audience = {"audience_id": AUDIENCE, "target_uri": TARGET_URI, "route": None}
    config = {
        "local": {
            "bind": f"127.0.0.1:{client_port}",
            "default_route": "primary",
            "request_lifetime_secs": 60,
            "max_in_flight": 8,
        },
        "identity": {"key_id": CLIENT_KEY_ID, "signing_key_seed_path": str(work / "client.seed")},
        "remote": {
            "addr": f"127.0.0.1:{tap_port}",
            "expected_server_name": SERVER_NAME,
            "client_cert_path": str(secrets / "client" / "client-tls.pem"),
            "client_key_path": str(secrets / "client" / "client-tls.key"),
            "server_ca_path": str(secrets / "server" / "client-ca.pem"),
        },
        "trust": {
            "manifest_path": str(work / "trust-anchors.json"),
            "profile": "mcp-re-http-v1",
            "org_keys": [{"kid": ORG_KID, "public_key": org_pub}],
            "floor": {"kind": "ephemeral"},
            "reload_secs": 300,
        },
        "delegation": {
            "verifier_audiences": [AUDIENCE],
            "expected_audience_hash": AUDIENCE,
            "accepted_epochs": [EPOCH],
            "max_clock_skew": 60,
        },
        "routes": [
            {
                "route_id": "primary",
                "target_uri": TARGET_URI,
                "audience": audience,
                # The server refuses a request whose evidence block binds no artifact.
                "extra_headers": [{"name": "Authorization", "value": "Bearer acceptance-token"}],
                "artifact_bindings": [
                    {"artifact_type": "oauth-dpop", "source": {"kind": "header", "name": "Authorization"}}
                ],
            }
        ],
    }
    path = work / "client.json"
    path.write_text(json.dumps(config, indent=2))
    return path


def read_http(sock):
    """One HTTP/1.1 message: (head, body). The client sends `Connection: close` and the proxy
    answers with a length, so a read to EOF or to Content-Length is complete."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head, body


def proxy_connection(secrets):
    ctx = ssl.create_default_context(cafile=str(secrets / "server" / "client-ca.pem"))
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ctx.load_cert_chain(str(secrets / "client" / "client-tls.pem"), str(secrets / "client" / "client-tls.key"))
    raw = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=15)
    return ctx.wrap_socket(raw, server_hostname=SERVER_NAME)


def exchange_with_proxy(secrets, raw_request):
    with proxy_connection(secrets) as upstream:
        upstream.sendall(raw_request)
        head, body = read_http(upstream)
    return head, body


class Tap(socketserver.ThreadingTCPServer):
    """Terminates the client's mTLS, forwards to the proxy as the evaluation client, records
    the request, and modifies it when `tamper` is set."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, secrets):
        super().__init__(("127.0.0.1", 0), _TapHandler)
        self.secrets = secrets
        self.tamper = False
        self.recorded = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(
            str(secrets / "server" / "server-chain.pem"), str(secrets / "server" / "server-key.pem")
        )


class _TapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        tap: Tap = self.server  # type: ignore[assignment]
        with tap.context.wrap_socket(self.request, server_side=True) as client:
            head, body = read_http(client)
            if tap.tamper:
                assert b"hello" in body, "the call under test carries the text the tap alters"
                body = body.replace(b"hello", b"HELLO")
            raw = head + b"\r\n\r\n" + body
            tap.recorded.append(raw)
            upstream_head, upstream_body = exchange_with_proxy(tap.secrets, raw)
            client.sendall(upstream_head + b"\r\n\r\n" + upstream_body)


class Run:
    def __init__(self, args):
        self.args = args
        self.work = Path(tempfile.mkdtemp(prefix="mcp-re-e2e-"))
        self.secrets = self.work / "compose" / "secrets"
        self.compose_dir = self.work / "compose"
        self.project = f"mcpre-e2e-{os.getpid()}"
        self.children = []
        self.checks = []

    def compose(self, *args, check=True):
        env = dict(os.environ, COMPOSE_PROJECT_NAME=self.project)
        return subprocess.run(
            ["docker", "compose", *args], cwd=self.compose_dir, env=env, check=check,
            capture_output=True, text=True,
        )

    def check(self, name, ok, detail=""):
        self.checks.append((name, ok))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"\n       {detail}"))
        if not ok:
            raise SystemExit(self.fail())

    def fail(self):
        print("---- proxy log (tail) ----", file=sys.stderr)
        tail = self.compose("logs", "--no-color", "--tail", "400", "proxy", check=False)
        print(tail.stdout + tail.stderr, file=sys.stderr)
        print("RELEASE ARTIFACT E2E: FAIL")
        return 1

    def spawn(self, argv, env=None, log="process"):
        sink = open(self.work / f"{log}.log", "wb")
        child = subprocess.Popen(argv, env=env, stdout=sink, stderr=sink)
        self.children.append(child)
        return child

    def wait_port(self, port):
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.2)
        raise SystemExit(f"nothing listening on {port}: see {self.work}")

    def counter(self):
        url = f"http://127.0.0.1:{self.backend_port}/call-count"
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.load(r)

    def refusals(self, reason):
        """How many requests the proxy has audited as rejected for `reason`. The proxy's own
        refusal is unsigned, so the client cannot relay its reason; the audit line is where
        the proxy states it. The container, and so its log, survives `compose restart`."""
        log = self.compose("logs", "--no-color", "proxy").stdout
        return log.count(f"event=mcp-re.request.rejected decision=Rejected reason={reason} ")

    def call(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.client_port, timeout=30)
        conn.request("POST", "/", json.dumps(CALL), {"Content-Type": "application/json"})
        reply = conn.getresponse()
        return reply.status, reply.read().decode()

    def ready(self):
        ready = subprocess.run(["./verify.sh", "ready"], cwd=self.compose_dir, capture_output=True, text=True)
        self.check("the proxy is ready and fails closed", ready.returncode == 0, ready.stderr)

    def restart(self, *services):
        self.compose("restart", *services)
        self.ready()

    def setup(self):
        shutil.copytree(COMPOSE_SRC, self.compose_dir, ignore=shutil.ignore_patterns("secrets", ".env"))
        subprocess.run(["./dev-pki.sh"], cwd=self.compose_dir, check=True, capture_output=True)
        self.backend_port = registry_port("mcp_re_inner_backend")
        env = (self.compose_dir / "env.example").read_text().splitlines()
        values = {
            "MCP_RE_VERSION": self.args.version,
            "REDIS_PASSWORD": b64url(os.urandom(18)),
            "MCP_RE_INNER_URL": f"http://host.docker.internal:{self.backend_port}/mcp/",
        }
        lines = [f"{k}={values[k]}" if k in values else line
                 for line in env for k in [line.split("=", 1)[0]]]
        lines += [f"MCP_RE_UID={os.getuid()}", f"MCP_RE_GID={os.getgid()}"]
        (self.compose_dir / ".env").write_text("\n".join(lines) + "\n")

        backend_env = dict(
            os.environ,
            MCP_RE_INNER_BACKEND_PORT=str(self.backend_port),
            MCP_RE_INNER_BACKEND_HOST="0.0.0.0",
            MCP_RE_INNER_BACKEND_ALLOWED_HOSTS=f"host.docker.internal:{self.backend_port}",
            MCP_RE_INNER_BACKEND_CALL_COUNTER="1",
        )
        self.spawn([sys.executable, str(ROOT / "tools" / "fastmcp_inner_backend.py")], backend_env, "backend")
        self.wait_port(self.backend_port)

        self.compose("up", "-d")
        self.ready()

        self.tap = Tap(self.secrets)
        threading.Thread(target=self.tap.serve_forever, daemon=True).start()
        org_pub = publish_trust(self.work, self.secrets)
        self.client_port = registry_port("mcp_re_client")
        config = write_client_config(
            self.work, self.secrets, self.client_port, self.tap.server_address[1], org_pub
        )
        checked = subprocess.run([self.args.client, "--config", str(config), "--check"],
                                 capture_output=True, text=True)
        self.check("the released client accepts its configuration and trust anchors",
                   checked.returncode == 0, checked.stderr)
        self.spawn([self.args.client, "--config", str(config)], log="client")
        self.wait_port(self.client_port)

    def scenario(self):
        self.check("backend has seen nothing yet", self.counter() == {"posts": 0, "tools_call": 0})

        status, body = self.call()
        self.check("a signed call is admitted and answered by the backend",
                   status == 200 and "hello" in body, f"{status} {body}")
        self.check("the backend received exactly that call",
                   self.counter() == {"posts": 1, "tools_call": 1}, str(self.counter()))
        admitted = self.tap.recorded[-1]

        before = self.refusals("mcp-re.digest_mismatch")
        self.tap.tamper = True
        status, body = self.call()
        self.tap.tamper = False
        self.check("a call modified in flight is not answered", '"error"' in body and "hello" not in body.lower(), f"{status} {body}")
        self.check("the proxy refused it as a digest mismatch", self.refusals("mcp-re.digest_mismatch") == before + 1)
        self.check("the backend received nothing for it",
                   self.counter() == {"posts": 1, "tools_call": 1}, str(self.counter()))

        for when in ("", " after the proxy restarted", " after Redis restarted"):
            if "proxy" in when:
                self.restart("proxy")
            elif "Redis" in when:
                self.restart("redis", "proxy")
            before = self.refusals("mcp-re.replay_detected")
            exchange_with_proxy(self.secrets, admitted)
            self.check(f"the admitted request, replayed{when}, is refused as a replay",
                       self.refusals("mcp-re.replay_detected") == before + 1)
            self.check(f"the backend received nothing for it{when}",
                       self.counter() == {"posts": 1, "tools_call": 1}, str(self.counter()))

        # A restarted primary needs a few seconds to resync its replica; until the replay quorum
        # acknowledges, the proxy refuses (fail closed), and a refused call never reaches the
        # backend, which the exact counts below confirm.
        for _ in range(30):
            status, body = self.call()
            if "hello" in body:
                break
            time.sleep(2)
        self.check("a fresh signed call is admitted after the restarts",
                   status == 200 and "hello" in body, f"{status} {body}")
        self.check("the backend received exactly the two admitted calls",
                   self.counter() == {"posts": 2, "tools_call": 2}, str(self.counter()))

    def teardown(self):
        for child in self.children:
            child.terminate()
        self.compose("down", "--volumes", check=False)
        shutil.rmtree(self.work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--client", required=True, help="the released mcp-re-client executable")
    parser.add_argument("--version", required=True, help="the published image tag, for example 0.19.0")
    args = parser.parse_args()
    run = Run(args)
    try:
        run.setup()
        run.scenario()
    finally:
        run.teardown()
    print("RELEASE ARTIFACT E2E: PASS")


if __name__ == "__main__":
    main()
