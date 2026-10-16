#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the whole ceiling campaign on the measurement host, then pack the run directory.
# Started inside tmux so an SSH drop cannot end it:
#   tmux new -d -s ceiling "bash /srv/mcp-re/tooling/tools/perf/lightsail/run_campaign.sh <run-id> <bundle-id>"
#
# The declared context (32 vCPU, x86_64, >= 120 GiB) is the default. rehearse_host.sh, and
# only it, overrides it for a smaller local host with EXPECT_VCPUS / EXPECT_ARCH /
# EXPECT_MEM_GIB and shrinks the sweep with CAMPAIGN_ARGS; every value used is recorded in
# logs/launcher.txt, so a run made with overrides says so.
set -uo pipefail
RUN_ID="${1:?run id}"
BUNDLE="${2:?bundle id}"
ROOT="${ROOT:-/srv/mcp-re}"
TOOLS="$ROOT/tooling/tools/perf/lightsail"
RUN="$ROOT/runs/$RUN_ID"
mkdir -p "$RUN/logs"
# File descriptors are raised to the hard limit and RECORDED; nothing else is tuned.
ulimit -n "$(ulimit -Hn)"
EXPECT_VCPUS="${EXPECT_VCPUS:-32}"
EXPECT_ARCH="${EXPECT_ARCH:-x86_64}"
EXPECT_MEM_GIB="${EXPECT_MEM_GIB:-120}"
read -r -a EXTRA <<< "${CAMPAIGN_ARGS:-}"
{
  echo "nofile=$(ulimit -n)"
  echo "expect_vcpus=$EXPECT_VCPUS expect_arch=$EXPECT_ARCH expect_mem_gib=$EXPECT_MEM_GIB"
  echo "campaign_args=${CAMPAIGN_ARGS:-}"
} > "$RUN/logs/launcher.txt"
python3 "$TOOLS/ceiling.py" campaign "$RUN" --bin-dir "$ROOT/bin" \
  --identity "$ROOT/stage/identity.json" --build-identity "$ROOT/build-identity.json" \
  --ports-toml "$ROOT/tooling/config/ports.toml" --bundle "$BUNDLE" \
  --expect-vcpus "$EXPECT_VCPUS" --expect-arch "$EXPECT_ARCH" --expect-mem-gib "$EXPECT_MEM_GIB" \
  --require-telemetry ${EXTRA[@]+"${EXTRA[@]}"} > "$RUN/logs/campaign.stdout" 2>&1
rc=$?
echo "campaign_rc=$rc" >> "$RUN/logs/launcher.txt"
cp "$ROOT/build-identity.json" "$ROOT/build.log" "$RUN/host/" 2>/dev/null || true
tar -C "$ROOT/runs" -czf "$ROOT/runs/$RUN_ID.tar.gz" "$RUN_ID"
( cd "$ROOT/runs" && sha256sum "$RUN_ID.tar.gz" > "$RUN_ID.tar.gz.sha256" )
echo "CAMPAIGN DONE rc=$rc -> $ROOT/runs/$RUN_ID.tar.gz"
