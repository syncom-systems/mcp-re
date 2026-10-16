#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearse the Lightsail host lifecycle locally: runbook §10 steps 0 and 3-7 against a local
# Ubuntu 24.04 container standing in for the instance. No cloud is contacted.
#
# The stand-in is the `ubuntu_24_04` blueprint's baseline and nothing more: the `ubuntu` user
# with passwordless sudo, openssh-server, python3 (cloud-init's own interpreter). Every
# package the run needs beyond that is installed by bootstrap.sh, exactly as on the instance.
# The rendered user-data runs as root, as cloud-init runs it, and installs the run's SSH key.
#
# Then the runbook's own commands, over SSH to 127.0.0.1:<port>:
#   3  stage dir, scp of the four staged files, tooling extract, inventory precheck
#   4  bootstrap.sh — packages, subject identity, Bazel at the subject's pin, the native
#      `bazel build -c opt` of the six instruments FROM THE STAGED RELEASE, build identity
#   5  run_campaign.sh inside tmux, with a shrunken sweep (CAMPAIGN_ARGS) and the stand-in's
#      own expectations — the launcher records both; it also refuses binaries whose SHA-256
#      differs from build-identity.json
#   6  scp download and the two checksum verifications
#   7  the stand-in is deleted
#
# What it cannot rehearse: the cloud calls (steps 1, 2, 8), and the instance's architecture
# when the local Docker host is not x86_64 — bootstrap then fetches the subject's pinned
# Bazel for the local arch, and the build/link of the x86_64 toolchain is NOT exercised.
# Its numbers describe a container on a developer box: a plumbing verdict, never a measurement.
#
# Usage: tools/perf/lightsail/rehearse_host.sh <run-id>      (run id like lightsail-rehearsal-<stamp>)
set -euo pipefail
cd "$(dirname "$0")/../../.."

RUN_ID="${1:?usage: rehearse_host.sh <run-id>}"
W="work/lightsail/$RUN_ID"
NAME="mcp-re-rehearsal-$RUN_ID"
CAMPAIGN_ARGS="${CAMPAIGN_ARGS:---cores 1,2 --reps 2 --b-modes cold --b-repeats 1 --partitioned 1 --ladder 64,128 --gen-cap 3 --requests-per-connection 40}"
say() { printf '\n=== %s ===\n' "$*"; }
die() { printf 'REHEARSAL: FAIL — %s\n' "$*" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "REHEARSAL: INFRASTRUCTURE_UNAVAILABLE (no Docker)"; exit 2; }
[[ -z "$(docker ps -aq --filter "name=^$NAME\$")" ]] || die "container $NAME exists"

say "0 — local staging"
tools/perf/lightsail/stage_artifacts.sh "$RUN_ID"
mkdir -p "$W/ssh"
ssh-keygen -q -t ed25519 -N '' -C "mcp-re-ceiling-$RUN_ID" -f "$W/ssh/id_ed25519"
read -r KTYPE KB64 _ < "$W/ssh/id_ed25519.pub"
python3 tools/cloud/render_cloud_config.py --template tools/perf/lightsail/cloud/user-data.sh \
  --run-id "$RUN_ID" --set SSH_KEY_TYPE="$KTYPE" --set SSH_KEY_B64="$KB64" --set RUN_ID="$RUN_ID"
python3 tools/cloud/render_cloud_config.py --template tools/perf/lightsail/cloud/firewall.json \
  --run-id "$RUN_ID" --set OPERATOR_CIDR="127.0.0.1/32"
USERDATA="$PWD/work/cloud-runs/$RUN_ID/user-data.sh"
[[ -s "$USERDATA" ]] || die "no rendered user-data at $USERDATA"

say "stand-in instance (ubuntu_24_04 baseline + rendered user-data)"
# Privileged: a VM has the whole kernel; an unprivileged container would push Bazel off its
# linux-sandbox and change what the build rehearses. Nothing in the run writes a global sysctl.
docker run -d --name "$NAME" --privileged --hostname "$NAME" -p 127.0.0.1::22 \
  -v "$USERDATA:/var/lib/cloud/user-data.sh:ro" ubuntu:24.04 bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends sudo openssh-server python3 >/dev/null
    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-cloud-init-users
    chmod 0440 /etc/sudoers.d/90-cloud-init-users
    usermod -p "*" ubuntu
    bash /var/lib/cloud/user-data.sh
    mkdir -p /run/sshd
    touch /var/lib/cloud/instance-ready
    exec /usr/sbin/sshd -D -e' >/dev/null
trap 'docker logs --tail 20 "$NAME" >&2 2>&1 || true' ERR
for _ in $(seq 1 120); do
  docker exec "$NAME" test -e /var/lib/cloud/instance-ready 2>/dev/null && break
  sleep 2
done
docker exec "$NAME" test -e /var/lib/cloud/instance-ready || die "the stand-in never became ready"
PORT="$(docker port "$NAME" 22/tcp | head -1 | sed 's/.*://')"
IP=127.0.0.1
VCPUS="$(docker exec "$NAME" nproc)"
ARCH="$(docker exec "$NAME" uname -m)"
MEM_GIB="$(docker exec "$NAME" awk '/MemTotal/ {printf "%d", $2/1048576}' /proc/meminfo)"
echo "stand-in: $NAME ssh=$IP:$PORT vcpus=$VCPUS arch=$ARCH mem_gib=$MEM_GIB"

# From here, runbook §10's commands with `-p/-P $PORT` added (the instance listens on 22).
SSH="ssh -p $PORT -i $W/ssh/id_ed25519 -o UserKnownHostsFile=$W/ssh/known_hosts -o StrictHostKeyChecking=accept-new -o BatchMode=yes ubuntu@$IP"
SCP="scp -P $PORT -i $W/ssh/id_ed25519 -o UserKnownHostsFile=$W/ssh/known_hosts -o BatchMode=yes"
for _ in $(seq 1 30); do $SSH true 2>/dev/null && break; sleep 1; done

say "3 — stage onto the host, inventory precheck"
$SSH 'sudo install -d -o ubuntu /srv/mcp-re /srv/mcp-re/stage'
$SCP "$W/subject.tar.gz" "$W/tooling.tar.gz" "$W/identity.json" "$W/SHA256SUMS" "ubuntu@$IP:/srv/mcp-re/stage/"
$SSH "cd /srv/mcp-re && tar -xzf stage/tooling.tar.gz && python3 /srv/mcp-re/tooling/tools/perf/lightsail/ceiling.py \
  inventory /srv/mcp-re/precheck --bundle rehearsal --expect-vcpus $VCPUS --expect-arch $ARCH --expect-mem-gib $MEM_GIB" \
  > "$W/precheck.out" || die "inventory precheck refused the stand-in (see $W/precheck.out)"

say "4 — bootstrap and native build"
started=$(date +%s)
$SSH 'cd /srv/mcp-re && sudo -E bash /srv/mcp-re/tooling/tools/perf/lightsail/bootstrap.sh' 2>&1 | tee "$W/bootstrap.out" || true
grep -q '^=== BOOTSTRAP: PASS' "$W/bootstrap.out" || die "bootstrap did not pass (see $W/bootstrap.out)"
echo "bootstrap_seconds=$(( $(date +%s) - started ))" | tee "$W/bootstrap.timing"

say "5 — campaign (shrunken sweep) inside tmux"
$SSH "tmux new -d -s ceiling 'EXPECT_VCPUS=$VCPUS EXPECT_ARCH=$ARCH EXPECT_MEM_GIB=$MEM_GIB CAMPAIGN_ARGS=\"$CAMPAIGN_ARGS\" bash /srv/mcp-re/tooling/tools/perf/lightsail/run_campaign.sh $RUN_ID rehearsal'"
for _ in $(seq 1 720); do
  $SSH "test -e /srv/mcp-re/runs/$RUN_ID.tar.gz.sha256" 2>/dev/null && break
  sleep 10
done
$SSH "cat /srv/mcp-re/runs/$RUN_ID/logs/launcher.txt; tail -n 5 /srv/mcp-re/runs/$RUN_ID/logs/campaign.log" || true

say "6 — download and verify"
mkdir -p "$W/results"
$SCP "ubuntu@$IP:/srv/mcp-re/runs/$RUN_ID.tar.gz" "ubuntu@$IP:/srv/mcp-re/runs/$RUN_ID.tar.gz.sha256" "$W/results/"
(cd "$W/results" && shasum -a 256 -c "$RUN_ID.tar.gz.sha256" && tar -xzf "$RUN_ID.tar.gz" \
  && cd "$RUN_ID" && shasum -a 256 -c SHA256SUMS >/dev/null) || die "downloaded run does not verify"

python3 - "$W/results/$RUN_ID" <<'PY'
import json, sys
from pathlib import Path
run = Path(sys.argv[1])
launcher = (run / "logs" / "launcher.txt").read_text()
assert "campaign_rc=0" in launcher, launcher
steps = json.loads((run / "logs" / "steps.json").read_text())
failed = [x["step"] for x in steps if not x["ok"]]
assert not failed, f"failed steps: {failed}"
s = json.loads((run / "summary.json").read_text())
a = s["phase_a"]["scaling"]["rows"]
assert all(r["reps_valid"] == r["reps_total"] for r in a), a
assert {"scaling", "partitioned", "shipped-auto"} <= set(s["phase_b"]), set(s["phase_b"])
build = json.loads((run / "host" / "build-identity.json").read_text())
print("binaries:", build["binaries"])
print("phase A:", [(r["cores"], round(r["throughput_median"])) for r in a])
print("statement:", s["ceiling"]["statement"])
PY

say "7 — delete the stand-in"
trap - ERR
docker rm -f "$NAME" >/dev/null
[[ -z "$(docker ps -aq --filter "name=^$NAME\$")" ]] || die "stand-in $NAME still exists"
echo "REHEARSAL: PASS -> $W"
