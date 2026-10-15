#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap the Lightsail measurement host and build the SUBJECT's binaries on it.
#
# Runs ON the instance, from the extracted tooling archive, after stage_artifacts.sh's three
# files were copied to $ROOT/stage/. It contacts no cloud API: it installs OS packages, the
# repository's pinned Bazel (`.bazelversion` of the SUBJECT, checksum-verified), and builds.
#
#   1. packages: compiler, git, python3, redis, sysstat, iproute2, perf, tmux
#   2. subject identity: the archive's checksum, its embedded commit id, and the git TREE
#      re-derived from the extracted files must equal the staged identity — the binaries
#      are built from exactly the tagged tree or not at all
#   3. Bazel at the subject's pinned version, checksum-verified against its release digest
#   4. `bazel build -c opt` of the six instruments; copied to $ROOT/bin with SHA256SUMS
#   5. build identity: Bazel version, the subject's own performance-surface digest, the
#      lockfile digests
#
# Usage: sudo -E bash /srv/mcp-re/tooling/tools/perf/lightsail/bootstrap.sh   (ROOT defaults to /srv/mcp-re)
set -euo pipefail

ROOT="${ROOT:-/srv/mcp-re}"
STAGE="$ROOT/stage"
SUBJECT="$ROOT/subject"
BIN="$ROOT/bin"
OWNER="${SUDO_USER:-$(id -un)}"
say() { printf '\n=== %s ===\n' "$*"; }
die() { printf 'BOOTSTRAP REFUSED: %s\n' "$*" >&2; exit 1; }

for f in subject.tar.gz tooling.tar.gz identity.json SHA256SUMS; do
  [[ -s "$STAGE/$f" ]] || die "missing $STAGE/$f"
done
( cd "$STAGE" && sha256sum -c SHA256SUMS ) || die "staged files do not match their SHA256SUMS"
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$STAGE/identity.json" "$1"; }
PRODUCT_COMMIT="$(jget product_commit)"; PRODUCT_TREE="$(jget product_tree)"

say "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q build-essential git python3 redis-server redis-tools sysstat iproute2 \
  util-linux procps tmux curl ca-certificates zip unzip linux-tools-common "linux-tools-$(uname -r)" \
  || apt-get install -y -q build-essential git python3 redis-server redis-tools sysstat iproute2 \
       util-linux procps tmux curl ca-certificates zip unzip linux-tools-common
# The distribution's own Redis instance would be an unrelated tenant on the measured box.
systemctl disable --now redis-server >/dev/null 2>&1 || true

say "subject identity"
[[ "$(gzip -dc "$STAGE/subject.tar.gz" | git get-tar-commit-id)" == "$PRODUCT_COMMIT" ]] \
  || die "the subject archive does not carry commit $PRODUCT_COMMIT"
[[ ! -e "$SUBJECT" ]] || die "$SUBJECT exists; a subject tree is extracted once"
mkdir -p "$ROOT/tmp-extract"
tar -xzf "$STAGE/subject.tar.gz" -C "$ROOT/tmp-extract"
mv "$ROOT/tmp-extract/subject" "$SUBJECT" && rmdir "$ROOT/tmp-extract"
# Re-derive the git tree from the files. Equality with the tag's tree is the proof that the
# build input is the tagged tree byte for byte (content, modes, symlinks, nothing added).
# `--force`: the tag tracks files its own .gitignore matches, and a plain `add -A` would
# silently leave them out and derive a different tree.
git -C "$SUBJECT" init -q
git -C "$SUBJECT" add -A --force
DERIVED_TREE="$(git -C "$SUBJECT" write-tree)"
[[ "$DERIVED_TREE" == "$PRODUCT_TREE" ]] || die "extracted tree $DERIVED_TREE != tagged tree $PRODUCT_TREE"
GIT_AUTHOR_NAME=subject GIT_AUTHOR_EMAIL=subject@invalid GIT_COMMITTER_NAME=subject \
GIT_COMMITTER_EMAIL=subject@invalid GIT_AUTHOR_DATE=@0 GIT_COMMITTER_DATE=@0 \
  git -C "$SUBJECT" commit -q -m "subject $PRODUCT_COMMIT (tree $PRODUCT_TREE)"
chown -R "$OWNER" "$SUBJECT"

say "bazel (pinned by the subject)"
BAZEL_VERSION="$(tr -d '[:space:]' < "$SUBJECT/.bazelversion")"
case "$(uname -m)" in x86_64) BARCH=x86_64 ;; aarch64) BARCH=arm64 ;; *) die "unsupported arch $(uname -m)" ;; esac
BURL="https://releases.bazel.build/$BAZEL_VERSION/release/bazel-$BAZEL_VERSION-linux-$BARCH"
curl -fsSL -o /usr/local/bin/bazel "$BURL"
curl -fsSL -o /tmp/bazel.sha256 "$BURL.sha256"
[[ "$(sha256sum /usr/local/bin/bazel | cut -d' ' -f1)" == "$(cut -d' ' -f1 /tmp/bazel.sha256)" ]] \
  || die "bazel $BAZEL_VERSION does not match its published digest"
chmod 0755 /usr/local/bin/bazel

say "build the instruments from the subject (-c opt)"
TARGETS=(mcp_re_proxy_deploy_bin mcp_re_proxy_ext_bin tls_load_harness_bench saturation_rig saturation_backend saturation_loadgen)
NAMES=(mcp-re-proxy-deploy mcp-re-proxy-ext tls_load_harness_bench saturation_rig saturation_backend saturation_loadgen)
LABELS=(); for t in "${TARGETS[@]}"; do LABELS+=("//mcp-re-proxy:$t"); done
sudo -u "$OWNER" -H bash -c "cd '$SUBJECT' && bazel build -c opt ${LABELS[*]}" 2>&1 | tee "$ROOT/build.log"
mkdir -p "$BIN"
for i in "${!TARGETS[@]}"; do
  out="$(sudo -u "$OWNER" -H bash -c "cd '$SUBJECT' && bazel cquery -c opt --output=files //mcp-re-proxy:${TARGETS[$i]}" 2>/dev/null | head -1)"
  [[ -n "$out" && -x "$SUBJECT/$out" ]] || die "no executable output for ${TARGETS[$i]}"
  install -m 0755 "$SUBJECT/$out" "$BIN/${NAMES[$i]}"
done
( cd "$BIN" && sha256sum "${NAMES[@]}" > SHA256SUMS )
chown -R "$OWNER" "$BIN"

say "build identity"
SURFACE="$(cd "$SUBJECT" && python3 -c 'import sys; sys.path.insert(0, "scripts"); import slo_evidence_identity as s; print(s.performance_surface()[0])')"
python3 - "$ROOT/build-identity.json" "$BAZEL_VERSION" "$SURFACE" "$BIN/SHA256SUMS" "$SUBJECT" <<'PY'
import hashlib, json, platform, subprocess, sys
out, bazel, surface, sums, subject = sys.argv[1:6]
def sha(p):
    return "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
record = {
    "bazel_version": bazel,
    "bazel_reported": subprocess.run(["bazel", "--version"], capture_output=True, text=True).stdout.strip(),
    "product_performance_surface": surface,
    "module_bazel_lock": sha(f"{subject}/MODULE.bazel.lock"),
    "crates_lock": sha(f"{subject}/bazel/crates.lock"),
    "compilation_mode": "opt",
    "host": {"arch": platform.machine(), "kernel": platform.release()},
    "binaries": dict(reversed(line.split()) for line in open(sums) if line.strip()),
}
json.dump(record, open(out, "w"), indent=2, sort_keys=True)
print(json.dumps(record, indent=2, sort_keys=True))
PY
chown "$OWNER" "$ROOT/build-identity.json" "$ROOT/build.log"
say "BOOTSTRAP: PASS — instruments built from $PRODUCT_COMMIT (tree $PRODUCT_TREE)"
