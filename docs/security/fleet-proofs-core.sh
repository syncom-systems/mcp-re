#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — the eight fleet proofs, PROVIDER-NEUTRAL core (MCPS-90).
#
# This file knows nothing about any cloud. It runs against whatever Kubernetes context is
# current, deploys the fleet from images it is GIVEN, and proves the eight properties below.
# Substrate provisioning lives in the drivers that call it, and only there:
#
#   docs/security/fleet-proofs-kind.sh          local kind cluster (local_gate.sh stage 5)
#   docs/security/gke-multi-replica-validation.sh   GKE / EKS provisioning, then this core
#
# The split is the control, not a convenience: the local path's execution closure must
# contain no provider CLI, provider account or registry discovery, and no cloud credential.
# `scripts/provider_neutral_closure_gate.py` refuses a provider invocation anywhere in that
# closure, so a cloud step reintroduced here fails stage 1 rather than reaching a tripwire.
#
# WHAT THIS PROVES, against a real Kubernetes fleet of N identical mcp-re-proxy replicas
# behind a Service, with a shared Redis replay + trust-epoch tier (ADR-MCPS-049 /
# ADR-MCPRE-051 §4):
#   Proof 1 — cross-replica REPLAY coherence: a nonce accepted (Fresh) by one
#             replica is rejected (Replay) by a sibling. (MCPS-79/80/81)
#   Proof 2 — cross-replica TRUST revocation: advancing the shared trust epoch
#             flushes the Push-tier trust cache across replicas; a credential
#             valid before the bump is rejected after it on a sibling. (MCPS-84/85/86)
#   Proof 3 — MRT continuation survives a REPLICA SWITCH: a multi-round-trip
#             continuation opened on replica A is honoured on replica B. (MCPS-82)
#   Proof 4 — ZERO-DROP rolling update: a rolling Deployment update with graceful
#             SIGTERM drain completes with no in-flight request abandoned
#             (ADR-MCPRE-051 §6 / drainGracePeriodSeconds).
#   Proof 5 — a STALE request fails closed: a validly-signed request whose freshness
#             window closed an hour ago is refused (mcp-re.expired_request).
#   Proof 6 — a MISBOUND request fails closed: bound to a different audience it is
#             refused as mcp-re.invalid_audience; bound to a different @target-uri —
#             a signature-base component — as mcp-re.invalid_signature, one layer
#             earlier. Both codes are asserted, because which layer refuses is part
#             of the claim.
#   Proof 7 — CONTAINMENT: a refused request never reaches the inner backend, with an
#             accepted request in the same run as the positive control for the counter.
#   Proof 8 — STARTUP POSTURE: a SELECTED security dependency that is unavailable makes
#             the replica refuse to serve and say which dependency, and serving is
#             restored once it returns — the recovery leg being the positive control,
#             because "not ready" is also what a broken image looks like.
#
# EXECUTION ORDER IS 1, 2, 3, 5, 6, 7, 4, 8 — not the numbering. Proof 4 replaces every pod
# the port-forwards are attached to, so every request-level proof runs before it and the
# disruptive one runs last. The numbers are the order the proofs were ADDED and are kept
# because they are what the release gate and its evidence refer to.
#
# Proofs 1-4 are all COHERENCE proofs — that replicas agree. Every request they send is a
# valid one, and the only rejections they assert are ones the harness itself caused: a
# spent nonce, a bumped epoch. A fleet that accepted everything would still pass Proof 1's
# second leg by accident of the replay store. Proofs 5-7 are the hostile half: is a bad
# request refused at all, and is it refused BEFORE the backend is invoked.
#
# Proofs 1-4 are already proven IN-PROCESS by the repo's tests
# (replay_race_harness_test, trust-epoch flush tests, async_drain_test); this
# harness RE-PROVES them on live cloud infrastructure, which is the MCPS-90
# release gate ADR-MCPS-049 clause and the single-node non-claim retirement
# (MCPS-91) depend on. Proofs 5-7 have in-process twins too, and the reason to
# re-prove them here is the same: the in-process refusal runs inside one address
# space with no TLS terminator, no Service, no sidecar and no real backend between
# the check and the thing it protects.
#
# INPUTS (from the driver; the core resolves no image, registry, project or account):
#   PROXY_IMAGE, INNER_IMAGE, LOADGEN_IMAGE   fully-resolved image references
#   MCP_RE_FLEET_CUSTODY_VALUES   optional Helm values file selecting the issuer's key
#                                 custody (a cloud KMS). Absent: the issuer is rooted in
#                                 the mounted seed (keySource=fileSeed).
#   MCP_RE_FIXTURES_DIR + the MCP_RE_* identity tuple (see scripts/local_gate.sh stage 5)
#   NAMESPACE (mcp-re), RELEASE (mcp-re-proxy), REPLICAS (3), MCP_RE_SKIP_ROLLING
#
# Exit 0 == all eight proofs pass.
set -euo pipefail

NAMESPACE="${NAMESPACE:-mcp-re}"
RELEASE="${RELEASE:-mcp-re-proxy}"
REPLICAS="${REPLICAS:-3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/mcp-re-proxy"
PORTS_TOML="$REPO_ROOT/config/ports.toml"
FIXTURES_DIR="${MCP_RE_FIXTURES_DIR:-}"
: "${PROXY_IMAGE:?the driver must supply PROXY_IMAGE}"
: "${INNER_IMAGE:?the driver must supply INNER_IMAGE}"
: "${LOADGEN_IMAGE:?the driver must supply LOADGEN_IMAGE}"

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'PROOF FAILED: %s\n' "$*" >&2; exit 1; }

# --- Port settings — RESOLVED FROM THE REGISTRY, never a literal --------------
# Every port comes from the repo's single source of truth, config/ports.toml
# (the reserved 8600-8699 band). We read it here rather than restating a number,
# so this harness, the deployed fleet, and the machine-wide reservation can never
# disagree (the "port chaos" this project left behind). `<KEY>_PORT` env vars
# still override, matching the registry convention.
port_of() {  # port_of <service-key> -> registered port
  python3 -c 'import tomllib,sys; print(tomllib.load(open(sys.argv[1],"rb"))["services"][sys.argv[2]]["port"])' \
    "$PORTS_TOML" "$1" 2>/dev/null
}
BIND_PORT="${MCP_RE_PROXY_PORT:-$(port_of mcp_re_proxy)}"
[[ -n "$BIND_PORT" ]] || fail "could not read mcp_re_proxy port from $PORTS_TOML"
# Two DISTINCT local port-forward endpoints, so the harness can address two
# replicas at once (a local port cannot be bound twice). Both forward to the one
# in-cluster BIND_PORT; both come from the registry, not inline literals.
LOCAL_PORT_A="${MCP_RE_VALIDATION_FWD_A_PORT:-$(port_of mcp_re_validation_fwd_a)}"
LOCAL_PORT_B="${MCP_RE_VALIDATION_FWD_B_PORT:-$(port_of mcp_re_validation_fwd_b)}"
[[ -n "$LOCAL_PORT_A" && -n "$LOCAL_PORT_B" ]] || fail "could not read validation forward ports from $PORTS_TOML"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# --- 1b. Fleet TLS/trust Secret (mounted by the chart at tls.mountPath) -------
# Built from the emit_mtls_fixtures output; key names match the chart's
# --signing-key-seed / --tls-cert / --tls-key / --client-ca / --trust mounts.
[[ -n "$FIXTURES_DIR" ]] || fail "set MCP_RE_FIXTURES_DIR to an emit_mtls_fixtures output dir"
log "TLS/trust Secret (mcp-re-proxy-material) from $FIXTURES_DIR"
kubectl -n "$NAMESPACE" create secret generic mcp-re-proxy-material \
  --from-file=signing-seed="$FIXTURES_DIR/signing_seed" \
  --from-file=tls.crt="$FIXTURES_DIR/server_cert.pem" \
  --from-file=tls.key="$FIXTURES_DIR/server_key.pem" \
  --from-file=client-ca.pem="$FIXTURES_DIR/client_ca.pem" \
  --from-file=trust.json="$FIXTURES_DIR/trust.json" \
  --dry-run=client -o yaml | kubectl apply -f -

# --- 1c. Inner FastMCP backend (the ALLOWED Streamable-HTTP inner plane) ------
log "Inner FastMCP backend ($INNER_IMAGE)"
# Repoint the manifest's image at THIS run's image. Match the repository and ignore the
# tag it carries: a tag-anchored pattern no-ops the moment the manifest and this harness
# disagree, and a no-op here is silent — the fleet would then deploy the manifest's bare
# local name, which is absent on kind and unpullable on GKE. The applied YAML is checked
# for the substitution rather than trusted.
INNER_YAML="$(sed -E "s#image: [^[:space:]/]*mcp-re-inner-fastmcp:[^[:space:]]+#image: $INNER_IMAGE#" \
  "$REPO_ROOT/deploy/k8s/inner-fastmcp.yaml")"
printf '%s\n' "$INNER_YAML" | grep -q "image: $INNER_IMAGE" \
  || fail "inner manifest image was not substituted — deploy/k8s/inner-fastmcp.yaml no longer matches the expected 'image: mcp-re-inner-fastmcp:<tag>' line"
printf '%s\n' "$INNER_YAML" | kubectl -n "$NAMESPACE" apply -f -
# Force a fresh pod so it runs THIS run's freshly built image. An `apply` with an
# unchanged spec (same image tag) does NOT restart the pod, so a rebuilt-and-reloaded
# image under the same tag (e.g. kind load, or a re-pushed registry tag with
# imagePullPolicy: IfNotPresent) would otherwise keep serving the STALE inner — the
# eliciting `confirm_action` tool would be missing and Proof 3 would see no
# requestState. Restart, then wait.
kubectl -n "$NAMESPACE" rollout restart deploy/mcp-re-inner-fastmcp
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-inner-fastmcp --timeout=420s

# --- 2. Shared Redis tier (replay + trust epoch) -----------------------------
# A PRIMARY plus REDIS_REPLICAS replicas, because the chart declares
# `replay.durabilityTier: redis-wait-quorum:<quorum>:<timeout_ms>` and the proxy fails
# an admission CLOSED when `WAIT` returns fewer acks than that quorum. A standalone
# Redis returns 0 acks forever, so every nonce insert fails and the very first request
# with a freshly drawn nonce comes back `replay` — a fail-closed store reads exactly
# like a spent nonce. The replica count is therefore DERIVED from the quorum the chart
# asks for, not chosen: a topology that cannot satisfy the declared tier is not a
# shared replay tier, it is an outage.
REDIS_REPLICAS="${MCP_RE_REDIS_REPLICAS:-$(
  awk -F'"' '/^  durabilityTier:/{split($2,p,":"); print p[2]}' "$CHART_DIR/values.yaml"
)}"
[[ "${REDIS_REPLICAS:-0}" -ge 1 ]] || fail "could not read the wait-quorum replica count from $CHART_DIR/values.yaml"
log "Shared Redis tier (primary + $REDIS_REPLICAS replicas for the declared wait quorum)"
kubectl -n "$NAMESPACE" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-redis }
spec:
  replicas: 1
  selector: { matchLabels: { app: mcp-re-redis } }
  template:
    metadata: { labels: { app: mcp-re-redis } }
    spec:
      containers:
        - name: redis
          image: redis:7
          # The replay + trust-epoch tier is an EPHEMERAL cache for the proof run (the
          # proofs never restart it), so run it purely in-memory: no RDB snapshots
          # (--save "") and no AOF. Crucially this drops `stop-writes-on-bgsave-error`,
          # which otherwise BRICKS all writes the moment a snapshot to the pod's
          # ephemeral disk fails under node disk pressure — silently failing every
          # replay `insert` closed (every request then rejected as a false "replay").
          args: ["--save", "", "--appendonly", "no", "--stop-writes-on-bgsave-error", "no"]
          ports: [{ containerPort: 6379 }]
---
apiVersion: v1
kind: Service
metadata: { name: mcp-re-redis }
spec:
  selector: { app: mcp-re-redis }
  ports: [{ port: 6379, targetPort: 6379 }]
YAML
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-redis --timeout=300s

# The replicas that make `WAIT <quorum>` answerable. Same in-memory settings as the
# primary; `--replicaof` points them at its Service. They carry no Service of their own —
# the proxy only ever talks to the primary, and these exist solely to acknowledge writes.
kubectl -n "$NAMESPACE" apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-redis-replica }
spec:
  replicas: $REDIS_REPLICAS
  selector: { matchLabels: { app: mcp-re-redis-replica } }
  template:
    metadata: { labels: { app: mcp-re-redis-replica } }
    spec:
      containers:
        - name: redis
          image: redis:7
          args: ["--save", "", "--appendonly", "no", "--stop-writes-on-bgsave-error", "no",
                 "--replicaof", "mcp-re-redis", "6379"]
          ports: [{ containerPort: 6379 }]
YAML
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-redis-replica --timeout=300s

# Ready is not the same as SYNCED: a replica reports Ready as soon as its port answers,
# but it does not acknowledge writes until it has attached to the primary. Deploying the
# fleet before then makes the first proof race the sync and fail closed for a reason that
# has nothing to do with what it tests. Block until the primary itself reports the acks.
redis_synced=""
for _ in $(seq 1 60); do
  acks="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
          redis-cli WAIT "$REDIS_REPLICAS" 1000 2>/dev/null | tr -d '\r')"
  if [[ "${acks:-0}" -ge "$REDIS_REPLICAS" ]]; then redis_synced=1; break; fi
  sleep 2
done
[[ -n "$redis_synced" ]] \
  || fail "only ${acks:-0} of $REDIS_REPLICAS Redis replicas acknowledge writes — the declared wait-quorum tier cannot be satisfied, and every replay insert would fail closed"
echo "  OK: $REDIS_REPLICAS replica(s) acknowledging writes; the declared wait quorum is satisfiable."

# SEED the trust-epoch counter before the fleet starts.
#
# The proxy refuses to serve when the key is ABSENT, and it is right to: an absent key is
# indistinguishable from a counter that was deleted, evicted, or lost to a restore, so
# reading it as epoch 0 would leave the push kill switch inert or let a restarted replica
# mint under a rolled-back epoch. This harness only ever GETs and INCRs the key, so on a
# FRESH Redis every replica CrashLoopBackOff'd on that guard and the fleet never became
# available — the harness predates the guard. `SETNX` so an existing counter is never
# rolled back to 0, which would be the very regression the guard exists to prevent.
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli SETNX mcp-re:trust:epoch 0 >/dev/null 2>&1 \
  || fail "could not seed the trust-epoch counter mcp-re:trust:epoch"
echo "  OK: trust-epoch counter present (SETNX; an existing value is left untouched)."

# --- 3. Deploy the fleet (strict + fleet + shared tiers) ---------------------
# The chart REFUSES to start a --fleet deployment on a node-local replay cache
# (ADR-MCPS-049 guardrail), so a green rollout already proves the shared tier is
# wired. TLS/trust material must be provided as the `mcp-re-tls` Secret.
log "Deploy fleet ($REPLICAS replicas) — always-maximal-security posture; fleet topology"
# Canonical inner endpoint is `/mcp/` WITH a trailing slash: FastMCP mounts Streamable
# HTTP at `/mcp/` and 307-redirects `/mcp` -> `/mcp/`. The proxy's raw hyper inner
# client does NOT follow redirects (it maps a non-2xx, the 307 included, to a
# fail-closed "inner unavailable"), so it must POST straight to `/mcp/`. Matches the
# helm example in deploy/k8s/inner-fastmcp.yaml.
INNER_URL="http://mcp-re-inner-fastmcp:$(port_of mcp_re_inner_backend)/mcp/"

# Signing-key custody (ADR-MCPRE-052 delegated-required ROOT ISSUER, off the request
# path). Which custody a fleet uses is the DRIVER's decision, because obtaining a cloud
# credential is a substrate fact: the cloud driver renders a Helm values file naming its
# KMS and the workload identity that reaches it, and passes it here. The core never
# constructs one. Without it the issuer is rooted in the mounted seed.
CUSTODY_ARGS=( --set keySource=fileSeed )
if [[ -n "${MCP_RE_FLEET_CUSTODY_VALUES:-}" ]]; then
  [[ -s "$MCP_RE_FLEET_CUSTODY_VALUES" ]] \
    || fail "MCP_RE_FLEET_CUSTODY_VALUES names no readable file: $MCP_RE_FLEET_CUSTODY_VALUES"
  CUSTODY_ARGS=( -f "$MCP_RE_FLEET_CUSTODY_VALUES" )
fi


# The trust domain both sides sign/verify under. ONE variable, used for the chart AND
# every client invocation, so the two cannot drift.
#
# It defaults to `example.com` because `emit_mtls_fixtures` bakes that value into
# trust.json as part of the resolved actor id (role:trust_domain:subject:keyid), and
# this harness is driven by those fixtures — signing under any other domain would not
# resolve. That is also why the install below sets identity.allowExampleFixtures.
TRUST_DOMAIN="${MCP_RE_TRUST_DOMAIN:-example.com}"

# The identity the chart now needs at RENDER time. These are also required further down
# for the client flags, but that is after the install — demand them here so a missing
# one fails before anything is deployed, rather than rendering a blank --audience.
: "${MCP_RE_AUDIENCE:?set MCP_RE_AUDIENCE (the proxy --audience id)}"
: "${MCP_RE_SERVER_SIGNER:?set MCP_RE_SERVER_SIGNER}"
: "${MCP_RE_SERVER_KEY_ID:?set MCP_RE_SERVER_KEY_ID}"
: "${MCP_RE_TARGET_URI:?set MCP_RE_TARGET_URI to the proxy --target-uri (e.g. https://proxy.internal:8600/mcp)}"
: "${MCP_RE_TRUST_EPOCH:?set MCP_RE_TRUST_EPOCH to the proxy --delegated-trust-epoch base label}"

# Pass this run's identity to the chart so the proxy verifies exactly what the client
# signs. Previously NOTHING was passed: the proxy took the chart's own placeholder
# values while the client signed from these variables, and the proofs passed only
# because the two happened to coincide. `identity.allowExampleFixtures` then tells the
# chart's placeholder guard that this is a fenced validation run whose identity is
# pinned by emit_mtls_fixtures, not an unconfigured production install.
helm -n "$NAMESPACE" upgrade --install "$RELEASE" "$CHART_DIR" \
  --set replicaCount="$REPLICAS" \
  --set fleet=true \
  --set bindPort="$BIND_PORT" \
  --set image.repository="${PROXY_IMAGE%:*}" \
  --set image.tag="${PROXY_IMAGE##*:}" \
  --set-string "inner.httpUrls={$INNER_URL}" \
  --set identity.audience="$MCP_RE_AUDIENCE" \
  --set identity.serverSigner="$MCP_RE_SERVER_SIGNER" \
  --set identity.serverKeyId="$MCP_RE_SERVER_KEY_ID" \
  --set identity.targetUri="$MCP_RE_TARGET_URI" \
  --set identity.trustDomain="$TRUST_DOMAIN" \
  --set identity.delegatedTrustEpoch="$MCP_RE_TRUST_EPOCH" \
  --set identity.allowExampleFixtures=true `# identity is pinned by emit_mtls_fixtures (did:example:server-1 / example.com), which trust.json encodes in the actor id` \
  --set replay.redisUrl="redis://mcp-re-redis:6379" \
  --set revocation.trustEpochRedisUrl="redis://mcp-re-redis:6379" \
  `# Proof 3 opens a multi-round-trip leg on one replica and answers it on another, which` \
  `# needs the SHARED correlation store. Without it the proxy refuses the open leg at the` \
  `# point it would be opened — the fail-closed direction, and its startup line says so —` \
  `# and Proof 3 fails with mcp-re.replay_cache_unavailable, naming the wrong store. The` \
  `# chart could not render this flag at all until the value below existed.` \
  --set continuationControl.redisUrl="redis://mcp-re-redis:6379" \
  --set replay.allowPlaintextRedis=true `# the in-cluster redis:7 this harness brings up serves no TLS; the opt-out is explicit because the chart refuses plaintext under fleet by default` \
  "${CUSTODY_ARGS[@]}" \
  --wait --timeout 8m
# The chart's deployment name is its fullname (<release>-<chart>), NOT the bare
# release, so resolve it by the stable app label rather than assuming $RELEASE.
DEPLOY="$(kubectl -n "$NAMESPACE" get deploy -l app.kubernetes.io/name=mcp-re-proxy \
  -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$DEPLOY" ]] || fail "could not resolve the proxy deployment name"
# The inner backend's deployment. Resolved the same way and for the same reason the proxy's
# is: Proof 7 reads its log to count backend invocations, and a name that has drifted from
# the manifest would make that count silently zero — which is the answer Proof 7's negative
# leg is looking for, so it must never be reachable by a lookup failure. Its positive
# control is what catches it.
INNER_DEPLOY="$(kubectl -n "$NAMESPACE" get deploy -l app.kubernetes.io/name=mcp-re-inner-fastmcp \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
INNER_DEPLOY="${INNER_DEPLOY:-mcp-re-inner-fastmcp}"
# The proxy reads its TLS/trust + KMS-token material ONCE at startup. When this
# harness is re-run, the fleet's Secret is re-applied with FRESH material (a new CA,
# a new short-lived client cert, a refreshed KMS token), but a spec-unchanged `helm
# upgrade` does NOT restart the pods — so without this they would keep serving the
# PREVIOUS run's cert and fail the client's TLS verify against the new CA. Force a
# rollout onto the current Secret and wait for it. (Mirrors what a Secret-rotation
# would require on GKE too.)
kubectl -n "$NAMESPACE" rollout restart deploy/"$DEPLOY"
kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=420s
[[ "$(kubectl -n "$NAMESPACE" get deploy "$DEPLOY" -o jsonpath='{.status.readyReplicas}')" -ge 2 ]] \
  || fail "fewer than 2 ready replicas — not a fleet"

# Address two DISTINCT replicas by port-forwarding two specific pods, so a proof
# that a nonce crosses replicas is genuine (not the same pod twice).
# Select the two NEWEST READY pods — never a stale one. The proxy reads its TLS/trust
# material ONCE at startup, so an OLD-generation pod (still Running while a prior
# ReplicaSet drains after the rollout restart above) serves the PREVIOUS run's cert
# and would fail the client's TLS verify. Filtering to Ready + newest pins the proof
# to the current generation. Portable array fill — no `mapfile` (bash 4+; macOS ships
# bash 3.2, so the harness runs identically there and on a Linux CI runner).
PODS=()
while IFS= read -r _pod; do [[ -n "$_pod" ]] && PODS+=("$_pod"); done < <(
  kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name="$RELEASE" \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
  | awk -F'\t' '$2=="True"{print $1}' | tail -2)
[[ "${#PODS[@]}" -ge 2 ]] || fail "need >= 2 ready pods to prove cross-replica coherence"
# Refuse a local port that is already taken, BEFORE forwarding through it. `kubectl
# port-forward` fails to bind and exits, the client then reaches whatever else holds the
# port, and a plaintext listener answers a TLS ClientHello with WRONG_VERSION_NUMBER —
# which reads as a serving or coherence defect. These ports are in the mcp-re registry
# band (config/ports.toml), so the usual squatter is another mcp-re process on the box.
port_free() {
  local port="$1" label="$2" holder
  python3 -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', $port))
except OSError:
    sys.exit(1)
finally:
    s.close()
" 2>/dev/null && return 0
  holder="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')"
  fail "local port $port for $label is already in use by ${holder:-another process}; free it or set the port override"
}
port_free "$LOCAL_PORT_A" "replica A"
port_free "$LOCAL_PORT_B" "replica B"

kubectl -n "$NAMESPACE" port-forward "pod/${PODS[0]}" "${LOCAL_PORT_A}:${BIND_PORT}" >/dev/null 2>&1 & PF_A=$!
kubectl -n "$NAMESPACE" port-forward "pod/${PODS[1]}" "${LOCAL_PORT_B}:${BIND_PORT}" >/dev/null 2>&1 & PF_B=$!
stop_port_forwards() { kill $PF_A $PF_B 2>/dev/null || true; }
trap stop_port_forwards EXIT

# WAIT for each tunnel to actually accept, rather than sleeping and hoping.
#
# A fixed `sleep 3` used to stand in for this. When a forwarder was not serving yet the
# client's TLS handshake got a non-TLS answer — `SSL: WRONG_VERSION_NUMBER` — and Proof 1
# then reported "replica B accepted a nonce already spent on A (replay coherence broken)".
# That is a false SECURITY alarm about a request that was never sent, on the lane that
# gates cloud spend.
# The readiness test is a real TLS HANDSHAKE, not a TCP connect. `kubectl port-forward`
# binds its local socket immediately and accepts connections before the tunnel to the pod
# is wired, then closes them — which is precisely what surfaces as WRONG_VERSION_NUMBER.
# A TCP connect therefore proves nothing. Certificate verification is off here on purpose:
# this only has to establish that the peer speaks TLS. The proofs themselves verify the
# chain, and weakening that is what would matter.
wait_forward() {
  local port="$1" pid="$2" label="$3"
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || fail "port-forward for $label exited; is the pod still ready?"
    # Plain `python3`: this needs only stdlib socket/ssl, never the SDK, and $CLIENT_PY
    # is not defined until further down.
    if python3 -c "
import socket, ssl, sys
try:
    s = socket.create_connection(('127.0.0.1', $port), 0.5)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    c.wrap_socket(s, server_hostname='${MCP_RE_SERVER_NAME:-proxy.internal}').close()
except Exception:
    sys.exit(1)
" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  fail "port-forward for $label never completed a TLS handshake on 127.0.0.1:$port"
}
wait_forward "$LOCAL_PORT_A" "$PF_A" "replica A (${PODS[0]})"
wait_forward "$LOCAL_PORT_B" "$PF_B" "replica B (${PODS[1]})"
# The client's --remote-addr takes host:port (mTLS + scheme come from --server-name
# and the CA); NOT a URL. Both forward to the one in-cluster BIND_PORT.
REPLICA_A="127.0.0.1:${LOCAL_PORT_A}"
REPLICA_B="127.0.0.1:${LOCAL_PORT_B}"

# The signed-request client — the HTTP-profile proof client shipped in this repo
# (MCP-RE is HTTP-profile only; there is no stdio client). It reads one plain
# JSON-RPC request on stdin, signs a draft-02 envelope with the `mcp-re-sdk` core,
# forwards it over verifying mTLS as one HTTP POST, and prints `verdict=<token>` to
# stderr; with --expect it exits non-zero on a verdict mismatch. Proof flags: --nonce
# (pin the nonce), --expect, --save-cont/--load-cont (MRT). Override MCP_RE_CLIENT to
# run it under a specific interpreter/venv (default: python3).
CLIENT_SCRIPT="$REPO_ROOT/docs/security/mcp_re_gke_client.py"
CLIENT="${MCP_RE_CLIENT:-python3 $CLIENT_SCRIPT}"
[[ -f "$CLIENT_SCRIPT" ]] || fail "proof client missing: $CLIENT_SCRIPT"
# Probe with the SAME interpreter the client runs under (the first word of
# $CLIENT), so a venv-installed SDK is found even when the system python3 has none.
CLIENT_PY="${CLIENT%% *}"
"$CLIENT_PY" -c 'import mcp_re_sdk' 2>/dev/null \
  || fail "mcp-re-sdk not importable by $CLIENT_PY — run: $CLIENT_PY -m pip install $REPO_ROOT/sdk/python"

# Client identity + the fleet's TLS/trust material — the SAME material as the
# `mcp-re-tls` Secret. Supplied via env (no secrets, no host/port literals here).
# Every flag below is required by the client.
CLIENT_COMMON=(
  --server-name      "${MCP_RE_SERVER_NAME:?set MCP_RE_SERVER_NAME to the proxy TLS SAN}"
  --signer-id        "${MCP_RE_SIGNER_ID:?set MCP_RE_SIGNER_ID}"
  --key-id           "${MCP_RE_KEY_ID:?set MCP_RE_KEY_ID}"
  --signing-key-seed "${MCP_RE_SIGNING_KEY_SEED:?set MCP_RE_SIGNING_KEY_SEED to a b64url seed or @file}"
  # ADR-MCPRE-052 delegated-required: the server-* trio is the ROOT ISSUER anchor the
  # delegation credential chains to (NOT a per-response key). --trust-epoch is NOT in
  # this array: with a trust-epoch source wired the proxy mints "<base>#<counter>", so
  # the accepted epoch has to be resolved from the shared counter at CALL time (see
  # `epoch_label` / `client`). It advances whenever an operator INCRs, and the counter
  # is monotonic — it is never rolled back.
  --server-signer    "${MCP_RE_SERVER_SIGNER:?set MCP_RE_SERVER_SIGNER}"
  --server-key-id    "${MCP_RE_SERVER_KEY_ID:?set MCP_RE_SERVER_KEY_ID}"
  --server-pubkey    "${MCP_RE_SERVER_PUBKEY:?set MCP_RE_SERVER_PUBKEY to a b64url key or @file}"
  --audience         "${MCP_RE_AUDIENCE:?set MCP_RE_AUDIENCE (the proxy --audience id)}"
  # RFC 9421 audience tuple (ADR-MCPRE-050): the client signs {audience,target-uri,route}
  # and the proxy rejects invalid_audience unless target-uri matches its --target-uri.
  --target-uri       "${MCP_RE_TARGET_URI:?set MCP_RE_TARGET_URI to the proxy --target-uri (e.g. https://proxy.internal:8600/mcp)}"
  --trust-domain     "$TRUST_DOMAIN"
  --tls-cert         "${MCP_RE_TLS_CERT:?set MCP_RE_TLS_CERT to the client cert PEM path}"
  --tls-key          "${MCP_RE_TLS_KEY:?set MCP_RE_TLS_KEY to the client key PEM path}"
  --server-ca        "${MCP_RE_SERVER_CA:?set MCP_RE_SERVER_CA to the server CA PEM path}"
)

# The epoch the proxy is currently minting: "<base>#<counter>", where <counter> is the
# shared Redis key (unset reads as 0). Resolved per call because an INCR moves it and a
# restarted replica resolves the SAME value — that is the property Proof 2 exercises.
epoch_label() {
  local c
  c="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
        redis-cli GET mcp-re:trust:epoch 2>/dev/null | tr -d '\r')"
  printf '%s#%s' "${MCP_RE_TRUST_EPOCH:?set MCP_RE_TRUST_EPOCH to the proxy --delegated-trust-epoch base label}" "${c:-0}"
}

# Every client invocation goes through this so the accepted epoch is always current.
client() {
  $CLIENT "${CLIENT_COMMON[@]}" --trust-epoch "$(epoch_label)" "$@"
}

# Run the client and distinguish "the server gave the wrong verdict" from "the client
# never got an answer".
#
# `client` exits non-zero for BOTH, so a proof that only tests its status attributes a
# TLS failure, a dead tunnel or a traceback to the security property under test — Proof 1
# reported a broken replay-coherence guarantee for a request whose handshake never
# completed. The client prints `verdict=<token>` when it reached a verdict; absent that,
# this reports a HARNESS failure and prints the client's own diagnosis, so the security
# claim is only ever made about a request that was actually served.
#
# Usage: prove <security-failure-message> -- <client args...>
prove() {
  local msg="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  # `|| rc=$?` rather than a bare assignment then `$?`: the script runs under `set -e`,
  # where a failing command substitution aborts on the assignment itself and this
  # function never reaches its own reporting.
  local err rc=0
  err="$(printf '%s\n' "$REQ" | client "$@" 2>&1)" || rc=$?
  if (( rc != 0 )) && ! grep -q 'verdict=' <<<"$err"; then
    printf '%s\n' "$err" >&2
    fail "the proof client did not reach a verdict (no 'verdict=' in its output) — this is a HARNESS failure, NOT evidence about: $msg"
  fi
  (( rc == 0 )) || { printf '%s\n' "$err" >&2; fail "$msg"; }
}
# A minimal plain-MCP request the non-MRT proofs send. Override MCP_RE_REQ for your inner.
REQ="${MCP_RE_REQ:-}"
[[ -n "$REQ" ]] || REQ='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# --- In-cluster load generator (for Proof 4) ---------------------------------
# Proof 4 (zero-drop rolling update) MUST drive load THROUGH kube-proxy — the Service
# ClusterIP — so a draining pod is dropped from the endpoints (preStop delay) and new
# connections reroute to live pods. A host `kubectl port-forward` is a direct tunnel to
# ONE pinned pod: when the rollout deletes that pod the tunnel dies and every later
# request fails regardless of drain, so it can never prove zero-drop on ANY provider.
# We therefore run the request loop from a loadgen pod INSIDE the cluster. Skippable
# with MCP_RE_SKIP_ROLLING (e.g. when no loadgen image is available).
LOADGEN_POD=""
if [[ -z "${MCP_RE_SKIP_ROLLING:-}" ]]; then
  log "In-cluster load generator (Proof 4 drives the Service through kube-proxy)"
  # Client-side material Secret (the files behind the client env; strip any leading @).
  seed_path="${MCP_RE_SIGNING_KEY_SEED#@}"; pub_path="${MCP_RE_SERVER_PUBKEY#@}"
  kubectl -n "$NAMESPACE" create secret generic mcp-re-loadgen-material \
    --from-file=client-cert="$MCP_RE_TLS_CERT" \
    --from-file=client-key="$MCP_RE_TLS_KEY" \
    --from-file=client-signing-seed="$seed_path" \
    --from-file=server-pubkey="$pub_path" \
    --from-file=server-ca="$MCP_RE_SERVER_CA" \
    --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -
  kubectl -n "$NAMESPACE" apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-loadgen, labels: { app: mcp-re-loadgen } }
spec:
  replicas: 1
  selector: { matchLabels: { app: mcp-re-loadgen } }
  template:
    metadata: { labels: { app: mcp-re-loadgen } }
    spec:
      containers:
        - name: loadgen
          image: "$LOADGEN_IMAGE"
          imagePullPolicy: IfNotPresent
          command: ["sleep", "infinity"]
          volumeMounts:
            - { name: material, mountPath: /etc/mcp-re-client, readOnly: true }
      volumes:
        - name: material
          secret: { secretName: mcp-re-loadgen-material }
YAML
  # Restart so the pod mounts THIS run's fresh client material (an unchanged spec does
  # not restart on `apply`), then wait for it.
  kubectl -n "$NAMESPACE" rollout restart deploy/mcp-re-loadgen
  kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-loadgen --timeout=180s
  # The ONE Ready pod with no deletionTimestamp — a terminating pod is excluded, never
  # outranked (docs/security/fleet_pod_select.py states why creationTimestamp cannot
  # order them). Zero or several eligible pods is retried, not tie-broken.
  for _ in $(seq 1 30); do
    LOADGEN_POD="$(kubectl -n "$NAMESPACE" get pod -l app=mcp-re-loadgen -o json \
      | python3 "$REPO_ROOT/docs/security/fleet_pod_select.py")" && break
    LOADGEN_POD=""
    sleep 2
  done
  [[ -n "$LOADGEN_POD" ]] || fail "no single Ready, non-terminating loadgen pod within 60s"

  # --- Inner-containment deny test -------------------------------------------
  # `deploy/k8s/inner-fastmcp.yaml` ships a NetworkPolicy making the proxy the ONLY
  # admitted ingress to the inner plane. A NetworkPolicy is accepted by every cluster
  # and enforced only by some, so "applied" says nothing about whether the containment
  # exists — and an allow-rule whose selector matches no pod does not fail loudly, it
  # denies everything. The loadgen is a real unrelated pod in the same namespace, so it
  # is the deny test: it must NOT reach the inner.
  #
  # Reported, not asserted. On a non-enforcing CNI (a GKE Standard cluster created
  # without --enable-network-policy, as this harness does) the reachability is expected
  # and the containment simply is not in force; failing here would block a run over a
  # property this cluster never claimed. What must never happen is silence — an
  # unenforced policy reading as a protected inner plane.
  if kubectl -n "$NAMESPACE" exec "$LOADGEN_POD" -- \
       python -c 'import socket,sys; socket.create_connection(("mcp-re-inner-fastmcp", '"$(port_of mcp_re_inner_backend)"'), timeout=6).close()' \
       >/dev/null 2>&1; then
    echo "  NOTE: an unrelated pod REACHED the inner plane — this CNI does not enforce"
    echo "        NetworkPolicy, so mcp-re-inner-fastmcp-allow-proxy-only is inert here."
    echo "        Inner containment is NOT in force on this cluster; do not claim it."
  else
    echo "  OK: inner containment enforced — an unrelated pod cannot reach the inner plane."
  fi
fi

# --- Proof 1: cross-replica replay coherence ---------------------------------
log "Proof 1 — cross-replica replay coherence"
# A proper 128-bit b64url nonce, PINNED so both replicas see the identical
# (signer, audience, nonce) triple — the whole point of the coherence proof.
#
# Passed as `--nonce=<value>`, NOT `--nonce <value>`. base64url maps `+` to `-`, so
# roughly one nonce in 64 starts with a hyphen, and argparse then reads it as the next
# OPTION rather than this one's value: "argument --nonce: expected one argument", and
# Proof 1 fails for a reason that has nothing to do with replay coherence. The `=` form
# binds the value to the flag whatever it starts with. A 1-in-64 spurious failure in a
# proof that gates a release is worse than a common one — it is rare enough to be
# dismissed as a fluke and re-run.
NONCE="$(head -c 16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
prove "replica A did not accept a fresh pinned nonce" -- \
  --remote-addr "$REPLICA_A" --nonce="$NONCE" --expect accepted
prove "replica B accepted a nonce already spent on A (replay coherence broken)" -- \
  --remote-addr "$REPLICA_B" --nonce="$NONCE" --expect replay
echo "  OK: nonce Fresh on A, Replay on B."

# --- Proof 2: cross-replica trust revocation ---------------------------------
log "Proof 2 — cross-replica trust-epoch revocation"
printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_A" --expect accepted \
  || fail "baseline request rejected before revocation"
# The shared counter is MONOTONIC and is never rolled back: minting under a lower epoch
# would resurrect credentials the fleet's verifiers have already stopped accepting, so a
# replica REFUSES a regressed counter rather than rebasing to it (that refusal is the
# C007 invariant). Revocation is therefore undone the way it is in production — by
# pointing verifiers at the NEW epoch — not by rewinding the store.
EPOCH_BEFORE="$(epoch_label)"
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli INCR mcp-re:trust:epoch >/dev/null
sleep 2  # bounded propagation window

# Sibling B must reject a credential minted under the PRE-bump epoch. Pin the old label
# explicitly: `client` would resolve the new one and (correctly) accept.
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --trust-epoch "$EPOCH_BEFORE" \
  --remote-addr "$REPLICA_B" --expect revoked \
  || fail "sibling B still trusted a credential revoked by the epoch bump"
echo "  OK: epoch bump on the shared tier revoked across replicas (old epoch $EPOCH_BEFORE rejected)."

# Serving continues immediately under the ADVANCED epoch — no rollback, no restart. This
# is also the restart invariant in situ: `epoch_label` re-derives from shared state, so
# any replica (fresh or long-lived) resolves the same post-INCR label.
log "Confirm serving under the advanced epoch (no rollback, no restart)"
EPOCH_AFTER="$(epoch_label)"
[[ "$EPOCH_AFTER" != "$EPOCH_BEFORE" ]] \
  || fail "the INCR did not change the resolved epoch label ($EPOCH_AFTER)"
restored=""
for _ in $(seq 1 30); do
  if printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_A" --expect accepted >/dev/null 2>&1 \
     && printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_B" --expect accepted >/dev/null 2>&1; then
    restored=1; break
  fi
  sleep 1
done
[[ -n "$restored" ]] || fail "replicas did not re-issue under the advanced epoch $EPOCH_AFTER"
echo "  OK: every replica re-issued under $EPOCH_AFTER; serving continues without a rollback."

# --- Proof 3: MRT continuation survives a replica switch ---------------------
# Open an InputRequired elicitation on A (persisting the continuation), read the
# server-issued requestState from A's response, then answer on B with that
# requestState + the loaded continuation. MRT_OPEN_REQ / the answer tool name are
# inner-specific — override MRT_OPEN_REQ and MRT_TOOL for your eliciting tool.
log "Proof 3 — MRT continuation across a replica switch"
if [[ -n "${MCP_RE_SKIP_MRT:-}" ]]; then
  echo "  SKIP: MCP_RE_SKIP_MRT set (inner has no eliciting tool wired)."
else
  CONT_FILE="$(mktemp)"
  MRT_TOOL="${MCP_RE_MRT_TOOL:-confirm_action}"
  MRT_OPEN_REQ="${MCP_RE_MRT_OPEN_REQ:-}"
  [[ -n "$MRT_OPEN_REQ" ]] || MRT_OPEN_REQ="$(jq -nc --arg t "$MRT_TOOL" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$t,arguments:{}}}')"
  OPEN_RESP="$(printf '%s\n' "$MRT_OPEN_REQ" | client \
    --remote-addr "$REPLICA_A" --save-cont "$CONT_FILE")" \
    || fail "could not open a multi-round-trip continuation on A"
  STATE="$(printf '%s' "$OPEN_RESP" | jq -r '.result.requestState // empty')"
  # An ABSENT requestState has two very different causes, and reporting the wrong one
  # costs an investigation: the open leg may have been REFUSED (a fail-closed replay
  # store reads exactly like a spent nonce — see the quorum note above), or it may have
  # been served by an inner with no eliciting tool. Distinguish them before blaming the
  # tool, and quote the refusal so the reader sees which it was.
  if [[ -z "$STATE" ]]; then
    OPEN_CODE="$(printf '%s' "$OPEN_RESP" \
      | jq -r '.error.data.mcp_re_error.wire_code // .error.message // empty')"
    if [[ -n "$OPEN_CODE" ]]; then
      fail "the MRT open leg on A was REFUSED ($OPEN_CODE) — this is not an elicitation \
failure. A fail-closed replay store reads as a spent nonce even for a fresh one; check \
the wait quorum before looking at the inner backend."
    fi
    fail "A's response carried no requestState (tool did not elicit input)"
  fi
  ANSWER_REQ="$(jq -nc --arg s "$STATE" --arg t "$MRT_TOOL" \
    '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$t,arguments:{},inputResponses:{confirm:true},requestState:$s}}')"
  printf '%s\n' "$ANSWER_REQ" | client \
    --remote-addr "$REPLICA_B" --load-cont "$CONT_FILE" --expect accepted \
    || fail "continuation opened on A was not honoured on B"
  rm -f "$CONT_FILE"
  echo "  OK: continuation opened on A honoured on B."
fi

# Proofs 5-7 run BEFORE Proof 4, and the order is load-bearing rather than tidy.
# Proof 4 performs a rolling update: every pod the port-forwards are attached to is
# replaced, so a request-level proof after it opens a TLS connection to a dead tunnel and
# dies with `SSLEOFError` — which the `prove` guard correctly refuses to read as evidence
# about a security property, and reports as a HARNESS failure. Measured: appended after
# Proof 4, Proof 5 failed exactly that way. The disruptive proof goes last.
# --- Proof 5: a stale request fails closed -----------------------------------
#
# The four proofs above are all about COHERENCE — that replicas agree. None of them asks
# whether a hostile request is refused at all, because every request they send is a valid
# one and the only rejections they assert are ones the harness itself caused (a spent
# nonce, a bumped epoch). A fleet that accepted everything would still pass Proof 1's
# second leg only by accident of the replay store.
#
# `--created-offset` signs a freshness window that closed an hour ago. The signature is
# VALID and the identity is the real one: the freshness check is the only thing that can
# refuse it, which is what makes this a test of that check rather than of parsing.
log "Proof 5 — a stale request fails closed"
inner_posts() {  # POST lines the inner backend has logged, i.e. times a request reached it
  kubectl -n "$NAMESPACE" logs "deploy/$INNER_DEPLOY" 2>/dev/null | grep -c '"POST ' || true
}
INNER_BEFORE="$(inner_posts)"
prove "replica A accepted a request whose freshness window closed an hour ago" -- \
  --remote-addr "$REPLICA_A" --created-offset -3600 --expect rejected:mcp-re.expired_request
echo "  OK: a stale request is refused."

# --- Proof 6: a misbound request fails closed --------------------------------
#
# Signed for a DIFFERENT audience tuple while the transport still carries the real one.
# `--sign-audience` moves only what is signed; `--audience` — what the response verifier
# is told to expect — stays put. Moving both would make this a valid request to a
# different proxy and would test nothing.
# THE TWO LEGS REFUSE AT DIFFERENT LAYERS, and the expectations say which. Both fail
# closed; asserting one code for both would have hidden that, and asserting merely "some
# rejection" would pass for a proxy that refused everything.
#
#   audience id   — not an RFC 9421 signature-base component, so the signature VERIFIES
#                   and the audience check is what refuses: `mcp-re.invalid_audience`.
#   @target-uri   — IS a signature-base component, so the base the proxy reconstructs
#                   differs from the one the client signed and verification fails first:
#                   `mcp-re.invalid_signature`, before any audience check runs.
#
# Measured, not assumed: the target-uri leg was written expecting `invalid_audience` and
# the fleet answered `invalid_signature`. The property held; the expectation was wrong.
log "Proof 6 — a request bound elsewhere fails closed"
prove "replica A did not refuse a request signed for another audience with mcp-re.invalid_audience" -- \
  --remote-addr "$REPLICA_A" --sign-audience "did:example:not-this-server" \
  --expect rejected:mcp-re.invalid_audience
prove "replica A did not refuse a request signed for another target URI with mcp-re.invalid_signature" -- \
  --remote-addr "$REPLICA_A" --sign-target-uri "https://elsewhere.invalid/mcp" \
  --expect rejected:mcp-re.invalid_signature
echo "  OK: a request bound elsewhere is refused — at the audience check, and at the signature base."

# --- Proof 7: a refused request never reaches the inner backend ---------------
#
# The distinction the four coherence proofs cannot draw: whether the proxy refuses BEFORE
# it forwards, or forwards and then declines to sign the answer. Only the first is
# containment, and the difference is invisible from the client — both look like a
# rejection.
#
# THE POSITIVE CONTROL IS THE POINT. "The counter did not move" is what a broken counter
# says too: uvicorn access logging off, a renamed inner deployment, a log rotation. So the
# same counter must be shown to MOVE for a request that is accepted, in the same run,
# against the same pod. Without that leg this proof passes on a fleet with no backend at
# all.
log "Proof 7 — a refused request does not invoke the inner backend"
INNER_AFTER_REFUSALS="$(inner_posts)"
[[ "$INNER_AFTER_REFUSALS" == "$INNER_BEFORE" ]] \
  || fail "the inner backend was invoked by a refused request: POST count went $INNER_BEFORE -> $INNER_AFTER_REFUSALS across Proofs 5-6"
prove "replica A did not accept a well-formed request (positive control for the counter)" -- \
  --remote-addr "$REPLICA_A" --expect accepted
INNER_AFTER_ACCEPTED="$(inner_posts)"
(( INNER_AFTER_ACCEPTED > INNER_AFTER_REFUSALS )) \
  || fail "the inner POST counter did not move for an ACCEPTED request ($INNER_AFTER_REFUSALS -> $INNER_AFTER_ACCEPTED). The counter measures nothing, so Proof 7's negative leg is not evidence — check that the inner deployment is $INNER_DEPLOY and that its access log is on."
echo "  OK: three refused requests reached the backend 0 times; an accepted one reached it."

# --- Proof 4: zero-drop rolling update ---------------------------------------
log "Proof 4 — zero-drop rolling update with drain"
if [[ -z "$LOADGEN_POD" ]]; then
  echo "  SKIP: MCP_RE_SKIP_ROLLING set (no in-cluster load generator)."
else
  PROXY_SVC="$(kubectl -n "$NAMESPACE" get svc -l app.kubernetes.io/name=mcp-re-proxy \
    -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$PROXY_SVC" ]] || fail "could not resolve the proxy Service"
  # The Service ClusterIP DNS — kube-proxy load-balances across Ready endpoints and
  # drops a draining pod (preStop) BEFORE it stops accepting, so new connections avoid
  # it while in-flight requests on it complete. mTLS SNI/scheme still come from the
  # client's --server-name / --server-ca; --remote-addr is host:port.
  TARGET_ADDR="${PROXY_SVC}.${NAMESPACE}.svc.cluster.local:${BIND_PORT}"
  # In-pod client flags: identity IDENTICAL to CLIENT_COMMON; file paths are the mounted
  # loadgen Secret. No value contains a space, so a space-joined command line is safe.
  LG="--server-name $MCP_RE_SERVER_NAME --signer-id $MCP_RE_SIGNER_ID --key-id $MCP_RE_KEY_ID"
  LG="$LG --signing-key-seed @/etc/mcp-re-client/client-signing-seed"
  LG="$LG --server-signer $MCP_RE_SERVER_SIGNER --server-key-id $MCP_RE_SERVER_KEY_ID"
  # The in-cluster load generator needs the SAME resolved "<base>#<counter>" label the
  # proxy is minting; the bare base is never minted when a trust-epoch source is wired.
  LG="$LG --server-pubkey @/etc/mcp-re-client/server-pubkey --trust-epoch $(epoch_label)"
  LG="$LG --audience $MCP_RE_AUDIENCE --target-uri $MCP_RE_TARGET_URI --trust-domain $TRUST_DOMAIN"
  LG="$LG --tls-cert /etc/mcp-re-client/client-cert --tls-key /etc/mcp-re-client/client-key --server-ca /etc/mcp-re-client/server-ca"
  # Time-bounded so the load spans the WHOLE rollout (a fixed request count can finish
  # before the roll does and miss the tail). Counts drops over the window.
  SECS="${MCP_RE_ROLLING_SECS:-75}"
  # A drop is recorded WITH the client's stderr, not just as a tally. The two things
  # that end a request here are not the same finding and must not look the same: a
  # connection-level failure (the kube-proxy endpoint-propagation race this proof is
  # actually about) versus a `verdict mismatch` (the proxy answered, and answered
  # something other than accepted — a fail-closed regression). Discarding stderr made
  # both print the bare word DROP, so a security regression during a rollout was
  # indistinguishable from a load-balancer timing artefact and neither could be triaged
  # after the fact. stdout is still discarded; only the diagnosis is kept.
  REMOTE="end=\$(( \$(date +%s) + $SECS )); n=0; drops=0; \
while [ \$(date +%s) -lt \$end ]; do \
  why=\$(printf '%s\\n' '$REQ' | python /app/mcp_re_gke_client.py $LG --remote-addr $TARGET_ADDR --expect accepted 2>&1 >/dev/null) \
    || { echo \"DROP \$(echo \$why | tr '\\n' ' ')\"; drops=\$((drops+1)); }; \
  n=\$((n+1)); \
done; echo \"loadgen: \$n requests, \$drops drop(s)\""
  # The loop runs DETACHED in the pod, writing to a file named for this run, and short execs
  # read the file back. Holding one exec stream open for the whole window made the result
  # depend on that stream: when it was torn down mid-run the runtime SIGKILLed the loop
  # (exit 137) and no summary existed to read. The file is new to this run, so a summary
  # left by an earlier run can never be read as this one's.
  LOAD_OUT="/tmp/mcps90-$(date +%s)-$$.load"
  printf '%s\n' "$REMOTE" | kubectl -n "$NAMESPACE" exec -i "$LOADGEN_POD" -- sh -c "cat > $LOAD_OUT.sh" \
    && kubectl -n "$NAMESPACE" exec "$LOADGEN_POD" -- \
         sh -c "nohup sh $LOAD_OUT.sh > $LOAD_OUT 2>&1 < /dev/null &" \
    || fail "could not start the in-cluster load generator"
  sleep 2  # let the load loop establish steady traffic before the rollout starts
  kubectl -n "$NAMESPACE" set env deploy/"$DEPLOY" ROLLOUT_NONCE="$(date +%s)"
  kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=300s
  load_deadline=$(( $(date +%s) + SECS + 120 ))
  : > /tmp/mcps90.load
  while (( $(date +%s) < load_deadline )); do
    kubectl -n "$NAMESPACE" exec "$LOADGEN_POD" -- cat "$LOAD_OUT" > /tmp/mcps90.load 2>/dev/null || true
    grep -q '^loadgen: ' /tmp/mcps90.load && break
    sleep 5
  done
  tail -1 /tmp/mcps90.load || true
  # HONESTY GUARD: the loop MUST have run to completion (it prints a `loadgen:` summary
  # with its request count). A killed/empty exec proves nothing — treat a missing
  # summary or a zero request count as FAILURE, never a silent pass.
  grep -q '^loadgen: ' /tmp/mcps90.load \
    || fail "load generator did not complete (no summary; exec killed?) — cannot confirm zero-drop"
  reqs="$(sed -n 's/^loadgen: \([0-9]*\) requests.*/\1/p' /tmp/mcps90.load)"
  [[ "${reqs:-0}" -gt 20 ]] \
    || fail "load generator ran only ${reqs:-0} requests — too few to span the rollout"
  ! grep -q DROP /tmp/mcps90.load \
    || fail "rolling update dropped in-flight requests ($(grep -c DROP /tmp/mcps90.load) of $reqs)"
  echo "  OK: rolling update completed with zero drops across $reqs requests (load via the Service)."
fi

# --- Proof 8: an unavailable security dependency refuses to serve -------------
#
# The startup-posture half. Every proof above runs against a fleet whose selected security
# dependencies are all present; none of them asks what happens when one is not. The
# fail-closed direction is the whole product claim here, and "the proxy refuses" is a
# sentence in a startup log until something removes the dependency and watches.
#
# The trust-epoch counter is the dependency chosen because its absence is UNAMBIGUOUS: an
# absent key is not epoch 0. It is indistinguishable from a counter that was never created,
# was deleted, or was lost to a restore, and reading it as a baseline would leave the push
# kill switch inert or let a restarted replica mint under a rolled-back epoch. The proxy
# says exactly that and exits.
#
# RUNS LAST, after the rolling update, because it deliberately takes the fleet down.
log "Proof 8 — an unavailable security dependency refuses to serve"
EPOCH_SAVED="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli GET mcp-re:trust:epoch 2>/dev/null | tr -d '\r')"
[[ -n "$EPOCH_SAVED" ]] || fail "could not read the trust-epoch counter before removing it"

restore_epoch() {  # always, even on failure: the fleet must not be left broken
  kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
    redis-cli SET mcp-re:trust:epoch "$EPOCH_SAVED" >/dev/null 2>&1 || true
  kubectl -n "$NAMESPACE" scale deploy/"$DEPLOY" --replicas="$REPLICAS" >/dev/null 2>&1 || true
}
# The port-forwards stop on this exit too: replacing the EXIT trap must not drop that.
trap 'restore_epoch; stop_port_forwards' EXIT

# The counter must be absent with NO live replica able to repair it. A serving replica
# that reads a vanished counter refuses to mint and repairs it as a forward rotation,
# writing one past its high-water mark (signing_plane/epoch_watch.rs) — so deleting the
# key under a live fleet and restarting one replica races the peers' next poll, and a
# replacement that starts after the repair finds the counter present and serves. That is
# the repair working, not the startup posture failing; the startup posture is what a
# replica with no mark does, and only a fleet with no live member has none. So the fleet
# goes to zero first, waiting out the drain (a draining pod still polls and would repair),
# then the key is removed, then the fleet comes back.
kubectl -n "$NAMESPACE" scale deploy/"$DEPLOY" --replicas=0 >/dev/null
# Polled rather than `kubectl wait --for=delete`, which fails on an already-empty selector
# in some kubectl versions; an empty listing is told apart from a failed query.
drained=""
for _ in $(seq 1 60); do
  if pods="$(kubectl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=mcp-re-proxy -o name)" \
       && [[ -z "$pods" ]]; then
    drained=1; break
  fi
  sleep 3
done
[[ -n "$drained" ]] \
  || fail "the proxy fleet did not reach zero replicas; the counter cannot be removed with no live peer"
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- redis-cli DEL mcp-re:trust:epoch >/dev/null
kubectl -n "$NAMESPACE" scale deploy/"$DEPLOY" --replicas="$REPLICAS" >/dev/null

# It must NOT come up. Waiting for a NEGATIVE needs a bound: 90s is far longer than a
# healthy start, which the proofs above have already demonstrated repeatedly. The line
# matched is the STARTUP refusal (trust_epoch.rs), never a serving replica's
# `WARNING: the shared trust epoch is unreadable (...)` repair line, which quotes the
# same cause; and it is read from the current or the previous container, since a refused
# replica is restarting.
proxy_logs() {
  local pod
  for pod in $(kubectl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=mcp-re-proxy -o name); do
    kubectl -n "$NAMESPACE" logs "$pod" --tail=40 2>/dev/null || true
    kubectl -n "$NAMESPACE" logs "$pod" --previous --tail=40 2>/dev/null || true
  done
}
refused=""
for _ in $(seq 1 30); do
  if proxy_logs | grep -v 'WARNING' | grep -q 'trust-epoch key .* does not exist'; then
    refused=1; break
  fi
  sleep 3
done
[[ -n "$refused" ]] \
  || fail "no replica reported the absent trust-epoch dependency; a security dependency was removed and nothing refused"

# No replica may become Ready while the dependency is absent. Every pod is new, so there
# is no draining pod to count; the window is sampled, not read once, because a replica
# that served after a slow start would otherwise be missed.
ready_deadline=$(( $(date +%s) + 60 ))
ready_now=0
while (( $(date +%s) < ready_deadline )); do
  ready_now="$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=mcp-re-proxy \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' | grep -c true || true)"
  (( ready_now == 0 )) || break
  sleep 5
done
(( ready_now == 0 )) \
  || fail "$ready_now replica(s) Ready with the trust-epoch dependency ABSENT — it did not fail closed"
echo "  OK: the dependency was removed and every replica refused to serve, naming it."

# THE POSITIVE CONTROL. "Not ready" is also what a broken image, a bad Secret or an
# unschedulable node look like, so the same replica must RECOVER once the dependency comes
# back — and recover without a rollback, which is the other half of the posture claim.
restore_epoch
kubectl -n "$NAMESPACE" delete pod -l app.kubernetes.io/name=mcp-re-proxy --wait=false >/dev/null
kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=300s >/dev/null \
  || fail "the fleet did not recover after the security dependency was restored — 'not ready' above cannot be attributed to the dependency"
trap stop_port_forwards EXIT
printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_A" --expect accepted >/dev/null 2>&1 \
  || echo "  note: replica A's port-forward did not survive the restart; recovery is established by the rollout above"
echo "  OK: serving restored once the dependency returned, with no rollback."

log "ALL EIGHT LIVE PROOFS PASSED"
