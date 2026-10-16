#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Local smoke of the Lightsail orchestration with the REAL instruments, before any paid host.
#
# Cross-builds the six instruments for Linux (the repository's own --platforms, the same way
# scripts/stage_image_binaries.sh does), then runs a deliberately small campaign inside a
# local Ubuntu 24.04 container — the host's distribution — with a real host-local Redis
# primary + 2 replicas, sysstat telemetry and a CPU-partitioned point. It exercises the
# paths the selftest's fake instruments cannot: the binaries' environment contract, the rig's
# JSON, cores=0 (the shipped topology), the replay tier's WAIT-2 probe, taskset pinning.
#
# It builds from the CURRENT tree and says so: its numbers describe a container on a
# developer box and are a plumbing verdict, never a measurement of the subject. No cloud is
# contacted. This is NOT a substitute for scripts/local_gate.sh --with-kind.
#
# Usage: tools/perf/lightsail/local_smoke.sh [out-dir]   (default work/lightsail-smoke/<stamp>)
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT="${1:-work/lightsail-smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
CPUS="${SMOKE_CPUS:-4}"
git check-ignore -q "$OUT" || { echo "$OUT is not git-ignored" >&2; exit 2; }
mkdir -p "$OUT/bin"
OUT="$(cd "$OUT" && pwd)"

case "$(docker info --format '{{.Architecture}}' 2>/dev/null)" in
  aarch64|arm64) PLATFORM=//platforms:linux_arm64 ;;
  x86_64|amd64)  PLATFORM=//platforms:linux_x86_64 ;;
  *) echo "LIGHTSAIL SMOKE: INFRASTRUCTURE_UNAVAILABLE (no Docker)"; exit 2 ;;
esac
FLAGS=(-c opt "--platforms=$PLATFORM")
TARGETS=(mcp_re_proxy_deploy_bin mcp_re_proxy_ext_bin tls_load_harness_bench saturation_rig saturation_backend saturation_loadgen)
NAMES=(mcp-re-proxy-deploy mcp-re-proxy-ext tls_load_harness_bench saturation_rig saturation_backend saturation_loadgen)
LABELS=(); for t in "${TARGETS[@]}"; do LABELS+=("//mcp-re-proxy:$t"); done
bazel build "${FLAGS[@]}" "${LABELS[@]}"
for i in "${!TARGETS[@]}"; do
  f="$(bazel cquery "${FLAGS[@]}" --output=files "//mcp-re-proxy:${TARGETS[$i]}" 2>/dev/null | head -1)"
  install -m 0755 "$f" "$OUT/bin/${NAMES[$i]}"
done
( cd "$OUT/bin" && shasum -a 256 "${NAMES[@]}" > SHA256SUMS )
printf '{"release_tag":"smoke","product_commit":"%s (working tree, NOT the subject)","tooling_commit":"%s"}\n' \
  "$(git rev-parse HEAD)" "$(git rev-parse HEAD)" > "$OUT/identity.json"

docker run --rm --cpus "$CPUS" -e DEBIAN_FRONTEND=noninteractive \
  -v "$PWD/tools/perf/lightsail:/t:ro" -v "$PWD/config:/config:ro" -v "$OUT:/out" ubuntu:24.04 bash -c '
    set -e
    apt-get update -q >/dev/null
    apt-get install -y -q python3 redis-server redis-tools sysstat iproute2 procps util-linux net-tools >/dev/null
    ulimit -n "$(ulimit -Hn)"
    python3 /t/ceiling.py campaign /out/run --bin-dir /out/bin --identity /out/identity.json \
      --ports-toml /config/ports.toml --cores 1,2 --reps 2 --b-modes cold --b-repeats 1 \
      --partitioned 1 --ladder 64,128 --gen-cap 3 --requests-per-connection 40 --require-telemetry'

python3 - "$OUT/run" <<'PY'
import json, sys
from pathlib import Path
run = Path(sys.argv[1])
s = json.loads((run / "summary.json").read_text())
steps = json.loads((run / "logs" / "steps.json").read_text())
failed = [x["step"] for x in steps if not x["ok"]]
a = s["phase_a"]["scaling"]["rows"]
assert not failed, f"failed steps: {failed}"
assert all(r["reps_valid"] == r["reps_total"] for r in a), a
assert s["phase_a"]["shipped-auto"]["rows"][0]["reps_valid"] > 0
b = s["phase_b"]
assert {"scaling", "partitioned", "shipped-auto"} <= set(b), set(b)
assert all(r["verdicts"] for v in b.values() for r in v["rows"]), b
tel = json.loads(next(run.glob("phase-b/scaling/c1/attempt1/telemetry/summary.json")).read_text())
assert tel["available"] and "proxy" in tel["categories"] and "redis" in tel["categories"], tel.get("categories")
print("phase A:", [(r["cores"], round(r["throughput_median"])) for r in a])
print("phase B:", {k: [(r["cores"], r["verdicts"]) for r in v["rows"]] for k, v in b.items()})
print("statement:", s["ceiling"]["statement"])
PY
echo "LIGHTSAIL SMOKE: PASS -> $OUT/run"
