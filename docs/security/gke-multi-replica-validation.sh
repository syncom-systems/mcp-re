#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — the eight fleet proofs on a CLOUD substrate (GKE or EKS) (MCPS-90).
#
# This driver owns everything provider-specific and nothing else: it provisions (or reuses)
# the cluster, selects the registry the images come from, and decides the issuer's key
# custody and the workload identity that reaches it. It then runs
# docs/security/fleet-proofs-core.sh — the provider-neutral core the local kind driver
# (docs/security/fleet-proofs-kind.sh) runs too — so the proofs, chart, Secret and
# `--expect` assertions are identical on every substrate.
#
# The `gke-` in this file's name is HISTORICAL — it predates the eks substrate and is kept
# only because renaming it would rewrite CHANGELOG entries that record what was actually
# run. It is NOT reachable from scripts/local_gate.sh, and
# scripts/provider_neutral_closure_gate.py keeps it that way.
#
# Cost note: a small cluster + a Redis instance for the duration of the run. Tear down
# with `--teardown` when done. Running it is a cloud operation and needs the owner's GO.
#
# Prerequisites (GKE):
#   * a Google Cloud project with billing enabled; gcloud + kubectl + helm
#   * gcloud auth login && gcloud config set project <PROJECT_ID>
#   * the fleet TLS/trust material (MCP_RE_FIXTURES_DIR, emit_mtls_fixtures output)
#   * the `mcp-re-sdk` Python package installed (`pip install ./sdk/python`)
# EKS additionally: eksctl + the aws CLI, an ECR_REGISTRY holding this VERSION's images,
# and one run of docs/security/eks-kms-irsa-setup.sh (then export MCP_RE_AWS_KMS_ROLE_ARN).
#
# Usage:
#   PROJECT_ID=my-proj PROVIDER=gke docs/security/gke-multi-replica-validation.sh [--teardown]
#   PROVIDER=eks                    docs/security/gke-multi-replica-validation.sh [--teardown]
set -euo pipefail

PROVIDER="${PROVIDER:-gke}"
case "$PROVIDER" in
  gke|eks) ;;
  kind) printf 'the local substrate has its own driver: docs/security/fleet-proofs-kind.sh\n' >&2; exit 1 ;;
  *) printf 'PROVIDER must be gke|eks\n' >&2; exit 1 ;;
esac
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAMESPACE="${NAMESPACE:-mcp-re}"
RELEASE="${RELEASE:-mcp-re-proxy}"

AWS_REGION="${MCP_RE_AWS_REGION:-eu-north-1}"
EKS_CLUSTER="${EKS_CLUSTER:-mcp-re-fleet}"
EKS_NODES="${EKS_NODES:-2}"
# 2 vCPU / 8 GiB, free-tier-eligible: enough for a 3-replica fleet + Redis + inner,
# and NOT the declared-hardware class — this harness proves COHERENCE, never
# throughput. The §7 baseline is a separate run on a separate node group
# (docs/security/eks-slo-baseline-runbook.md), and its instance types cannot launch
# on a Free Tier plan at all.
EKS_MACHINE="${EKS_MACHINE:-m7i-flex.large}"

# PROJECT_ID targets EVERY gcloud call explicitly (never the ambient active config), so
# this driver can only ever act on the project the operator names. Defaults to the active
# gcloud project; must resolve to a real id.
if [[ "$PROVIDER" == gke ]]; then
  PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
  [[ -n "$PROJECT_ID" && "$PROJECT_ID" != "REPLACE_WITH_PROJECT_ID" ]] \
    || { printf 'set PROJECT_ID (no active gcloud project resolved)\n' >&2; exit 1; }
fi
CLUSTER="${CLUSTER:-mcp-re-fleet}"
REGION="${REGION:-us-central1}"
# The gke provider provisions a STANDARD, ZONAL cluster (NOT Autopilot, NOT regional):
# exactly the shape docs/security/gke-slo-baseline-runbook.md §2 declares, so the eight
# proofs and the §7 SLO baseline run on ONE capacity-correct cluster that fits the
# free-trial 16-vCPU CPUS_ALL_REGIONS cap. Autopilot (`create-auto`) + a regional
# placement (3x nodes) blow past that cap — the reason an earlier run FailedScheduling.
# REGION still names the Artifact Registry host (${REGION}-docker.pkg.dev); ZONE places
# the cluster. Two e2-standard-2 nodes = 4 vCPU: the fleet's default-pool.
ZONE="${ZONE:-us-central1-a}"
GKE_NODES="${GKE_NODES:-2}"
GKE_MACHINE="${GKE_MACHINE:-e2-standard-2}"
# Image tag — READ FROM THE REPO'S VERSION file, never restated as a literal: the chart's
# appVersion/image.tag and deploy/k8s/inner-fastmcp.yaml already track VERSION, so a tag restated here goes stale
# the moment VERSION moves and the fleet then names an image the registry does not hold.
IMAGE_TAG="${MCP_RE_IMAGE_TAG:-$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")}"
[[ -n "$IMAGE_TAG" ]] || { printf 'could not read the image tag from %s/VERSION\n' "$REPO_ROOT" >&2; exit 1; }
# Container images, from the substrate's registry (the chart's bare `mcp-re-proxy` name is
# unpullable on a cluster). Override with MCP_RE_PROXY_IMAGE / _INNER_ / _LOADGEN_.
if [[ "$PROVIDER" == gke ]]; then
  AR="${MCP_RE_AR:-${REGION}-docker.pkg.dev/${PROJECT_ID}/mcp-re}"
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-${AR}/mcp-re-proxy:$IMAGE_TAG}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-${AR}/mcp-re-inner-fastmcp:$IMAGE_TAG}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-${AR}/mcp-re-loadgen:$IMAGE_TAG}"
elif [[ "$PROVIDER" == eks ]]; then
  # ECR. The registry host is required rather than derived: deriving it from the
  # caller's account would silently pull from whatever account happens to be
  # authenticated, which is not the same guarantee as naming the one you meant.
  : "${ECR_REGISTRY:?set ECR_REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com (see docs/security/eks-slo-baseline-runbook.md)}"
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-${ECR_REGISTRY}/mcp-re-proxy:$IMAGE_TAG}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-${ECR_REGISTRY}/mcp-re-inner-fastmcp:$IMAGE_TAG}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-${ECR_REGISTRY}/mcp-re-loadgen:$IMAGE_TAG}"
fi

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'PROOF FAILED: %s\n' "$*" >&2; exit 1; }

if [[ "${1:-}" == "--teardown" ]]; then
  log "Teardown ($PROVIDER)"
  helm -n "$NAMESPACE" uninstall "$RELEASE" || true
  if [[ "$PROVIDER" == gke ]]; then
    gcloud container clusters delete "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" --quiet || true
  elif [[ "$PROVIDER" == eks ]]; then
    # --disable-nodegroup-eviction: the fleet's PodDisruptionBudget would otherwise
    # hold the drain open until the eksctl timeout, leaving a BILLING cluster behind
    # after a teardown that reported success.
    eksctl delete cluster --name "$EKS_CLUSTER" --region "$AWS_REGION" \
      --disable-nodegroup-eviction || true
  fi
  exit 0
fi
# --- 1. Cluster (idempotent create-or-reuse) ---------------------------------
if [[ "$PROVIDER" == gke ]]; then
  log "Cluster $CLUSTER (STANDARD, zonal $ZONE, Workload Identity) in $PROJECT_ID"
  if ! gcloud container clusters describe "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" >/dev/null 2>&1; then
    # --workload-pool enables Workload Identity: the KMS-rooted (keySource=gcpKms)
    # fleet authenticates to Cloud KMS with the GKE metadata-server token bound to a
    # GSA (roles/cloudkms.signerVerifier) — NO user access token (which KMS rejects
    # from inside GCP: ACCESS_TOKEN_TYPE_UNSUPPORTED), NO key material in the pod, NO
    # software-seed fallback. The default node pool created here gets GKE_METADATA
    # automatically. Run docs/security/gke-kms-wi-setup.sh once after this to bind the
    # GSA. fileSeed roots ignore all of this; WI just sits unused.
    #
    # --enable-network-policy installs Calico, which is what makes
    # `mcp-re-inner-fastmcp-allow-proxy-only` (deploy/k8s/inner-fastmcp.yaml) actually
    # filter packets. Without it the object is accepted and enforces NOTHING: the inner
    # plane speaks plain HTTP with no auth of its own, so any pod in the cluster could
    # POST straight past the PEP — no signature, no replay admission, no audit record.
    # A GKE run on a cluster without this proves the four coherence properties but NOT
    # inner containment, and the earlier v0.11/v0.12.1 runs were in exactly that state.
    # The SLO phase is unaffected: `tls_load_harness_bench` spawns its own proxy in-pod
    # and drives it over loopback (`https://localhost/`, echo backend on 127.0.0.1, the
    # Redis sidecars sharing the pod netns), so the measured path never crosses the CNI.
    gcloud container clusters create "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" \
      --num-nodes "$GKE_NODES" --machine-type "$GKE_MACHINE" --disk-size 30 --no-enable-basic-auth \
      --enable-network-policy \
      --workload-pool "${PROJECT_ID}.svc.id.goog"
  fi
  gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE"
elif [[ "$PROVIDER" == eks ]]; then
  log "Cluster $EKS_CLUSTER (EKS, $AWS_REGION, OIDC/IRSA) "
  if ! aws eks describe-cluster --name "$EKS_CLUSTER" --region "$AWS_REGION" >/dev/null 2>&1; then
    # --with-oidc provisions the cluster's OIDC identity provider. That is what makes
    # IRSA possible at all: without it EKS projects no service-account token and the
    # awsKms custody path below has no credentials, so the fleet would have to fall
    # back to a mounted IAM key pair — a weaker posture than the GKE run this harness
    # is supposed to be the twin of.
    eksctl create cluster --name "$EKS_CLUSTER" --region "$AWS_REGION" \
      --nodes "$EKS_NODES" --node-type "$EKS_MACHINE" --node-volume-size 40 \
      --with-oidc --managed
  fi
  aws eks update-kubeconfig --name "$EKS_CLUSTER" --region "$AWS_REGION"
  # NetworkPolicy on EKS is NOT enforced by default. The VPC CNI accepts the object
  # and filters nothing unless policy enforcement is switched on, which is exactly the
  # state the earlier GKE runs were in before --enable-network-policy: the four
  # coherence proofs pass and `mcp-re-inner-fastmcp-allow-proxy-only` enforces NOTHING,
  # so any pod in the cluster can POST past the PEP — no signature, no replay
  # admission, no audit record. Turn it on, and FAIL if it cannot be turned on rather
  # than running a fleet that reports inner containment it does not have.
  log "VPC CNI NetworkPolicy enforcement (inner containment)"
  aws eks update-addon --cluster-name "$EKS_CLUSTER" --region "$AWS_REGION" \
    --addon-name vpc-cni --resolve-conflicts PRESERVE \
    --configuration-values '{"enableNetworkPolicy":"true"}' >/dev/null \
    || fail "could not enable VPC CNI NetworkPolicy on $EKS_CLUSTER — without it the inner-plane NetworkPolicy is accepted and enforces nothing"
  aws eks wait addon-active --cluster-name "$EKS_CLUSTER" --region "$AWS_REGION" \
    --addon-name vpc-cni
fi
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# --- Signing-key custody: the substrate's KMS, reached by workload identity -------------
# ADR-MCPRE-052 delegated-required ROOT ISSUER, off the request path. The custody CODE is
# identical on every substrate; how the pod obtains its cloud credential is the one
# substrate-forced difference, and it is decided HERE, never in the core:
#   GKE  gcpKms via the Workload-Identity metadata server (useMetadata=true) — a user access
#        token is REJECTED from inside GCP (ACCESS_TOKEN_TYPE_UNSUPPORTED). Needs the cluster
#        made with --workload-pool (above) and docs/security/gke-kms-wi-setup.sh run once,
#        then MCP_RE_GCP_KMS_GSA=<gsa>@<project>.iam.gserviceaccount.com.
#   EKS  awsKms via IRSA — the projected token exchanged by STS (useWebIdentity=true). Needs
#        the cluster made --with-oidc (above) and docs/security/eks-kms-irsa-setup.sh run
#        once, then MCP_RE_AWS_KMS_ROLE_ARN.
# In both the pod holds NO key material and NO long-lived credential, which is the property
# a cloud run exists to demonstrate. MCP_RE_KEY_SOURCE=fileSeed roots the issuer in the
# mounted seed instead (no KMS at all); the default follows the substrate, so a run cannot
# silently prove custody on a cloud whose KMS it never touched.
KEY_SOURCE="${MCP_RE_KEY_SOURCE:-}"
[[ -n "$KEY_SOURCE" ]] || { [[ "$PROVIDER" == eks ]] && KEY_SOURCE=awsKms || KEY_SOURCE=gcpKms; }
CUSTODY_VALUES=""
case "$KEY_SOURCE:$PROVIDER" in
  gcpKms:gke)
    : "${MCP_RE_GCP_KEY_VERSION:?set MCP_RE_GCP_KEY_VERSION to the KMS signing key-version}"
    : "${MCP_RE_GCP_KMS_GSA:?export MCP_RE_GCP_KMS_GSA=<gsa>@<project>.iam.gserviceaccount.com (run gke-kms-wi-setup.sh first)}"
    CUSTODY_VALUES="$(mktemp -t mcp-re-custody.XXXXXX)"
    python3 -c 'import json,sys; json.dump({"keySource": "gcpKms",
        "gcpKms": {"keyVersion": sys.argv[1], "useMetadata": True},
        "serviceAccount": {"annotations": {"iam.gke.io/gcp-service-account": sys.argv[2]}}},
        open(sys.argv[3], "w"))' "$MCP_RE_GCP_KEY_VERSION" "$MCP_RE_GCP_KMS_GSA" "$CUSTODY_VALUES" ;;
  awsKms:eks)
    : "${MCP_RE_AWS_KMS_KEY_ID:?set MCP_RE_AWS_KMS_KEY_ID to the KMS signing key id/ARN/alias}"
    : "${MCP_RE_AWS_KMS_ROLE_ARN:?export MCP_RE_AWS_KMS_ROLE_ARN=arn:aws:iam::<acct>:role/<role> (run eks-kms-irsa-setup.sh first)}"
    CUSTODY_VALUES="$(mktemp -t mcp-re-custody.XXXXXX)"
    python3 -c 'import json,sys; json.dump({"keySource": "awsKms",
        "awsKms": {"region": sys.argv[1], "keyId": sys.argv[2], "useWebIdentity": True},
        "serviceAccount": {"annotations": {"eks.amazonaws.com/role-arn": sys.argv[3]}}},
        open(sys.argv[4], "w"))' "${MCP_RE_AWS_KMS_REGION:-$AWS_REGION}" "$MCP_RE_AWS_KMS_KEY_ID" \
        "$MCP_RE_AWS_KMS_ROLE_ARN" "$CUSTODY_VALUES" ;;
  fileSeed:*) ;;
  *) fail "MCP_RE_KEY_SOURCE=$KEY_SOURCE is not a custody PROVIDER=$PROVIDER can reach by workload identity (gke: gcpKms|fileSeed, eks: awsKms|fileSeed)" ;;
esac

export PROXY_IMAGE INNER_IMAGE LOADGEN_IMAGE NAMESPACE RELEASE
if [[ -n "$CUSTODY_VALUES" ]]; then export MCP_RE_FLEET_CUSTODY_VALUES="$CUSTODY_VALUES"; else unset MCP_RE_FLEET_CUSTODY_VALUES; fi
exec "$REPO_ROOT/docs/security/fleet-proofs-core.sh"
