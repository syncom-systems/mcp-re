#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — the eight fleet proofs on a LOCAL kind cluster (scripts/local_gate.sh stage 5).
#
# This driver provisions the substrate — a kind cluster and the locally-built images loaded
# into it — and then runs docs/security/fleet-proofs-core.sh, the provider-neutral proof
# core that the GKE/EKS driver (docs/security/gke-multi-replica-validation.sh) runs too.
# A green kind run is therefore the same eight proofs, against the same chart and images,
# as a cloud run, for free.
#
# Its execution closure contains NO cloud: no provider CLI, no account, project or registry
# discovery, no cloud credential and no cloud KMS. `scripts/provider_neutral_closure_gate.py`
# refuses a provider invocation anywhere in the closure of `scripts/local_gate.sh`, and the
# issuer is rooted in the mounted seed — cloud-KMS custody is proven by the cloud drivers and
# the KMS live lanes, never from here.
#
# Usage:
#   docs/security/fleet-proofs-kind.sh              # create-or-reuse, deploy, prove
#   docs/security/fleet-proofs-kind.sh --teardown   # delete the kind cluster
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIND_CLUSTER="${KIND_CLUSTER:-mcp-re-fleet}"

log() { printf '\n=== %s ===\n' "$*"; }
verdict() { printf '\nKIND FLEET PROOFS: %s\n' "$1"; }

if [[ "${1:-}" == "--teardown" ]]; then
  log "Teardown (kind)"
  kind delete cluster --name "$KIND_CLUSTER" || true
  exit 0
fi

case "${MCP_RE_KEY_SOURCE:-fileSeed}" in
  fileSeed) ;;
  *) printf 'the kind driver roots the issuer in the mounted seed only (MCP_RE_KEY_SOURCE=%s refused):\ncloud-KMS custody belongs to docs/security/gke-multi-replica-validation.sh\n' \
       "$MCP_RE_KEY_SOURCE" >&2; exit 1 ;;
esac

# Image tag — READ FROM THE REPO'S VERSION file, never restated as a literal: the chart's
# appVersion/image.tag and deploy/k8s/inner-fastmcp.yaml already track VERSION, so a tag
# restated here goes stale the moment VERSION moves and the fleet then names an absent image.
IMAGE_TAG="${MCP_RE_IMAGE_TAG:-$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")}"
[[ -n "$IMAGE_TAG" ]] || { printf 'could not read the image tag from %s/VERSION\n' "$REPO_ROOT" >&2; exit 1; }
# The locally-built tags, side-loaded with `kind load` (native arch — the same Dockerfiles
# a registry build uses). Override with MCP_RE_PROXY_IMAGE / _INNER_ / _LOADGEN_.
PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-mcp-re-proxy:$IMAGE_TAG}"
INNER_IMAGE="${MCP_RE_INNER_IMAGE:-mcp-re-inner-fastmcp:$IMAGE_TAG}"
LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-mcp-re-loadgen:$IMAGE_TAG}"

# kind: create-or-reuse a local cluster and load the SAME images the GKE build
# produces (native arch; the proxy's binary Bazel-built and staged). Build any
# image that isn't present locally, so a first run is self-contained.
log "kind cluster $KIND_CLUSTER (local substrate — no cloud spend)"
kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" \
  || kind create cluster --name "$KIND_CLUSTER"
kubectl config use-context "kind-${KIND_CLUSTER}" >/dev/null
# The loadgen image is built only when Proof 4 will use it. It was built
# unconditionally, so an image seven of the eight proofs never touch could take the whole
# lane down before a single proof ran — and did: `rust:1.94.1-slim-bookworm`, the wheel
# stage's base, failed `apt-get update` with "at least one invalid signature" on a host
# where `debian:bookworm-slim` and the proxy's own runtime stage both succeeded. An
# environmental fault in one image's base is not evidence about replay coherence,
# freshness, audience binding or containment, and it must not be able to look like it.
# The proxy image copies a Bazel-built binary for the node architecture; stage it first.
case "$(docker info --format '{{.Architecture}}' 2>/dev/null)" in
  aarch64|arm64) IMAGE_ARCH=arm64 ;;
  *) IMAGE_ARCH=amd64 ;;
esac
"$REPO_ROOT/scripts/stage_image_binaries.sh" --arch "$IMAGE_ARCH" \
  || { verdict "INFRASTRUCTURE_UNAVAILABLE"; exit 1; }
IMAGE_SPECS=("proxy:$PROXY_IMAGE:deploy/docker/Dockerfile"
             "inner:$INNER_IMAGE:deploy/docker/Dockerfile.inner")
[[ -n "${MCP_RE_SKIP_ROLLING:-}" ]] \
  || IMAGE_SPECS+=("loadgen:$LOADGEN_IMAGE:deploy/docker/Dockerfile.loadgen")
for img_spec in "${IMAGE_SPECS[@]}"; do
  tgt="${img_spec%%:*}"; rest="${img_spec#*:}"; img="${rest%:*}"; dfile="${rest##*:}"
  # Rebuild when the image does not match the SOURCE, not merely when it is absent.
  #
  # "Absent" alone is the wrong test. Image tags come from VERSION, so every commit
  # within a version reuses one tag: a `docker image inspect` hit is satisfied by an
  # arbitrarily old build. This lane is the documented precondition for cloud spend and
  # claims to run "the SAME image the GKE build produces", so a stale hit means the
  # gate validates an old binary against today's chart and passes. That is not
  # hypothetical — a 4-day-old proxy image was CrashLoopBackOff-ing on
  # `unknown flag --trust-reload-secs`, a flag the chart had gained and the binary
  # predated, while every other stage was green.
  #
  # So the built revision is stamped on the image and compared to HEAD. A dirty tree
  # always rebuilds: the commit alone cannot describe uncommitted source.
  src_rev="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]] && src_rev="${src_rev}-dirty"
  img_rev="$(docker image inspect --format \
    '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$img" 2>/dev/null || true)"
  if [[ "$img_rev" != "$src_rev" || "$src_rev" == *-dirty ]]; then
    if ! docker image inspect "$img" >/dev/null 2>&1; then
      log "build $img ($tgt) — not present locally"
    elif [[ "$src_rev" == *-dirty ]]; then
      log "rebuild $img ($tgt) — working tree is dirty; a commit cannot describe it"
    else
      log "rebuild $img ($tgt) — image revision '${img_rev:-none}' != source '$src_rev'"
    fi
    if [[ "$tgt" == proxy ]]; then
      docker build -f "$dfile" --target proxy \
        --build-arg "DIST=deploy/docker/dist/$IMAGE_ARCH" \
        --label "org.opencontainers.image.revision=$src_rev" -t "$img" "$REPO_ROOT"
    else
      docker build -f "$dfile" \
        --build-arg "DIST=deploy/docker/dist/$IMAGE_ARCH" \
        --label "org.opencontainers.image.revision=$src_rev" -t "$img" "$REPO_ROOT"
    fi
  else
    log "reuse $img ($tgt) — built from this exact revision ($src_rev)"
  fi
  log "kind load $img"
  kind load docker-image "$img" --name "$KIND_CLUSTER"
done
export PROXY_IMAGE INNER_IMAGE LOADGEN_IMAGE
unset MCP_RE_FLEET_CUSTODY_VALUES
exec "$REPO_ROOT/docs/security/fleet-proofs-core.sh"
