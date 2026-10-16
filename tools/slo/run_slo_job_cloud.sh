#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 SLO Job on a CLOUD node pool — provider resolution only.
#
# Resolves the two substrate facts a cluster Job needs — the registry the bench image is
# pulled from and the node-pool label that pins the declared machine class — and then runs
# the provider-neutral tools/slo/run_slo_job.sh, which owns the Job spec. Not reachable from
# scripts/local_gate.sh (scripts/provider_neutral_closure_gate.py keeps it that way); the
# local rehearsal calls the runner directly. Running it is a cloud operation and needs the
# owner's GO.
#
# Usage:
#   PROVIDER=gke BENCH_IMG=<region>-docker.pkg.dev/<project>/mcp-re/mcp-re-slo-bench:<VERSION> \
#     tools/slo/run_slo_job_cloud.sh <node-pool> <hw-class-label> <cores> <out.json>
#   PROVIDER=eks ECR_REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com \
#     tools/slo/run_slo_job_cloud.sh <nodegroup> <hw-class-label> <cores> <out.json>
#
# Then gate the pair (see docs/security/gke-slo-baseline-runbook.md):
#   python3 scripts/slo_gate.py --report e2_8core.json \
#     --baseline e2_1core.json --scaled e2_8core.json \
#     --targets docs/bench/adr-051-slo-targets.json
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER="${PROVIDER:?PROVIDER must be gke|eks}"
POOL="${1:?usage: run_slo_job_cloud.sh <node-pool> <hw-class> <cores> <out.json>}"
shift
# The tag is READ FROM VERSION, never restated: the registry holds the image at whatever
# VERSION says, so a literal goes stale on the next bump (ImagePullBackOff on a paid node).
BENCH_TAG="$(tr -d '[:space:]' < "$HERE/../../VERSION")"

case "$PROVIDER" in
  gke)
    # Named, never derived: a default project would be a project nobody chose for this run.
    : "${BENCH_IMG:?PROVIDER=gke needs BENCH_IMG=<region>-docker.pkg.dev/<project>/mcp-re/mcp-re-slo-bench:$BENCH_TAG}"
    NODE_LABEL="cloud.google.com/gke-nodepool=$POOL" ;;
  eks)
    if [[ -z "${BENCH_IMG:-}" ]]; then
      : "${ECR_REGISTRY:?PROVIDER=eks needs ECR_REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com (or set BENCH_IMG)}"
      BENCH_IMG="$ECR_REGISTRY/mcp-re-slo-bench:$BENCH_TAG"
    fi
    NODE_LABEL="eks.amazonaws.com/nodegroup=$POOL" ;;
  *) echo "PROVIDER must be gke|eks (got '$PROVIDER'); the local rehearsal is tools/slo/rehearse_job_spec.sh" >&2; exit 2 ;;
esac

export BENCH_IMG NODE_LABEL
PULL_POLICY="${PULL_POLICY:-IfNotPresent}" exec "$HERE/run_slo_job.sh" "$@"
