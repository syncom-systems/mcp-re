#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 SLO measurement as a Kubernetes Job — the PROVIDER-NEUTRAL runner.
#
# The Job runs the mcp-re-slo-bench image (deploy/docker/Dockerfile.bench), which runs
# tls_load_harness_bench — spawning the REAL mcp-re-proxy async fleet at
# MCP_RE_LOADGEN_CORES cores against an in-process echo backend over mTLS — under the pinned
# envelope (docs/bench/adr-051-benchmark-envelope.json), then extracts the report.
#
# This runner resolves no image, registry or node pool. It is given them:
#
#   BENCH_IMG=<image> [PULL_POLICY=..] [NODE_LABEL=key=value] \
#     tools/slo/run_slo_job.sh <hw-class-label> <cores> <out.json>
#
# Callers: tools/slo/rehearse_job_spec.sh (local kind, local_gate.sh stage 5) and
# tools/slo/run_slo_job_cloud.sh (GKE/EKS: resolves the registry image and the node-pool
# label, then runs this). The manifest is the literal template tools/slo/slo-job.yaml,
# rendered by tools/slo/render_slo_job.py — no shell ever evaluates template text.
#
# Env:
#   BENCH_IMG         (required)        the mcp-re-slo-bench image reference
#   PULL_POLICY       (IfNotPresent)    Never for a side-loaded image
#   NODE_LABEL        (none)            key=value node pinning for a declared class
#   NS                (mcp-re)          namespace
#   CPU_REQUEST       (6)               lower it only for a plumbing dry-run; a declared-
#   MEM_REQUEST       (2Gi)             hardware measurement keeps 6 / 2Gi
#   REDIS_IMG         (redis:7-alpine)  the sidecar image
#   WORKERS_PER_SHARD (0)               0 = shipped default; 1 for the scaling run
#   CONCURRENCY/REQUESTS (128/8000)     the canonical v2 envelope
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${NS:-mcp-re}"
: "${BENCH_IMG:?BENCH_IMG must name the bench image (the runner resolves no registry)}"

HW="${1:?usage: run_slo_job.sh <hw-class> <cores> <out.json>}"
CORES="${2:?cores, e.g. 1 or 8}"
OUT="${3:?output report path}"

JOB="slo-$(printf '%s' "$HW" | tr -d '.-' | tr 'A-Z' 'a-z')-${CORES}c"
MANIFEST="$(python3 "$HERE/render_slo_job.py" --template "$HERE/slo-job.yaml" \
  "JOB=$JOB" "NODE_LABEL=${NODE_LABEL:-}" "REDIS_IMG=${REDIS_IMG:-redis:7-alpine}" \
  "BENCH_IMG=$BENCH_IMG" "PULL_POLICY=${PULL_POLICY:-IfNotPresent}" "HW=$HW" "CORES=$CORES" \
  "WORKERS_PER_SHARD=${WORKERS_PER_SHARD:-0}" "CONCURRENCY=${CONCURRENCY:-128}" \
  "REQUESTS=${REQUESTS:-8000}" "CPU_REQUEST=${CPU_REQUEST:-6}" "MEM_REQUEST=${MEM_REQUEST:-2Gi}")"

kubectl -n "$NS" delete job "$JOB" >/dev/null 2>&1 || true
printf '%s\n' "$MANIFEST" | kubectl -n "$NS" apply -f - >/dev/null

echo "[$JOB] hw=$HW cores=$CORES image=$BENCH_IMG — waiting for completion..."
# 600s: the v2 canonical envelope runs 8000 requests/run, so a 1-core run needs a wide window.
kubectl -n "$NS" wait --for=condition=complete "job/$JOB" --timeout=600s 2>/dev/null \
  || kubectl -n "$NS" wait --for=condition=failed "job/$JOB" --timeout=10s 2>/dev/null || true

POD="$(kubectl -n "$NS" get pods -l job-name="$JOB" -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" logs "$POD" 2>&1 \
  | sed -n '/===REPORT_JSON_BEGIN===/,/===REPORT_JSON_END===/p' | sed '1d;$d' > "$OUT"

if [ -s "$OUT" ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT" 2>/dev/null; then
  python3 - "$OUT" "$HW/${CORES}c" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["results"]
s, f, lat = r["successes"], r["failures"], r["added_latency_us"]
print("  [%s] throughput=%.1f rps  p50=%dus p99=%dus p999=%dus  success=%d/%d"
      % (sys.argv[2], r["throughput_rps"], lat["p50"], lat["p99"], lat["p999"], s, s + f))
PY
  echo "  report -> $OUT"
else
  echo "[$JOB] NO VALID REPORT — last logs:"; kubectl -n "$NS" logs "$POD" 2>&1 | tail -20; exit 1
fi
